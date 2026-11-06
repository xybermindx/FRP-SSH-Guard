#!/usr/bin/env python3
"""Disposable systemd VM only, initially without an installed guard.

FRP_GUARD_DISPOSABLE=1 python3 tests/vm-behavior.py OLD.deb NEW.deb FRP_DIR
OLD.deb is the previous v0.0.7 build. Uses real frps/frpc, nftables and synthetic
documentation addresses. Takes about 40 minutes: the shortest rule is 15 minutes.
"""
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

spec = importlib.util.spec_from_file_location('vm', Path(__file__).with_name('vm-acceptance.py'))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
run, output, guard, wait_for = vm.run, vm.output, vm.guard, vm.wait_for
TABLE = 'frp_ssh_persistent_guard'
BACKEND = '''
import socket, threading
server = socket.socket(); server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 2222)); server.listen()
def serve(conn):
    conn.sendall(b"SSH-2.0-example\\r\\n" + b"x" * 40960)  # more than a failed login sends
    try: conn.recv(1)
    finally: conn.close()
while True:
    conn, _ = server.accept(); threading.Thread(target=serve, args=(conn,), daemon=True).start()
'''


def elements(name):
    document = json.loads(output('nft', '-j', 'list', 'set', 'inet', TABLE, name))
    result = {}
    for item in document['nftables']:
        for element in item.get('set', {}).get('elem', []):
            elem = element.get('elem', {}) if isinstance(element, dict) else {}
            key = elem.get('val', element)
            if isinstance(key, dict):
                key = ' '.join(map(str, key['concat']))
            result[key] = elem
    return result


def client(code):
    return run('ip', 'netns', 'exec', 'guard-client', 'python3', '-c', code, check=False)


def attempt(ip, port, timeout=0.5):
    return client('import socket; s=socket.socket(); s.settimeout(' + str(timeout) + '); s.bind(("' + ip
                  + '",0));\ntry: s.connect(("198.51.100.1",' + str(port) + ')); s.recv(64)\nexcept OSError: pass')


def rotate_until_banned(ip, set_name, minutes=25):
    """One connection to each of two ports every 30 seconds, as a slow bot would."""
    end = time.monotonic() + minutes * 60
    while time.monotonic() < end:
        if ip in elements(set_name):
            return
        for port in (22001, 22002):
            attempt(ip, port)
        time.sleep(30)
    raise AssertionError(f'{ip} was not banned in {set_name}')


def main():
    assert os.environ.get('FRP_GUARD_DISPOSABLE') == '1' and os.geteuid() == 0
    old, new, frp = [Path(p).resolve() for p in sys.argv[1:]]
    assert run('dpkg-query', '-W', 'frp-ssh-guard', check=False).returncode != 0
    run('useradd', '-m', 'guardbehavior')
    work = Path('/tmp/guard-behavior-test')
    work.mkdir(exist_ok=True)
    (work / 'frps.toml').write_text('bindPort = 7000\n')
    proxies = [(22001, 22), (22002, 22), (22003, 22), (22004, 2222)]
    (work / 'frpc.toml').write_text('serverAddr = "127.0.0.1"\nserverPort = 7000\n' + ''.join(
        f'[[proxies]]\nname = "example-behavior-{port}"\ntype = "tcp"\nlocalIP = "127.0.0.1"\n'
        f'localPort = {local}\nremotePort = {port}\n' for port, local in proxies))
    run('systemd-run', '--unit=guard-behavior-backend', 'python3', '-c', BACKEND)
    run('systemd-run', '--unit=guard-behavior-frps', str(frp / 'frps'), '-c', str(work / 'frps.toml'))
    wait_for(lambda: 'frps' in output('ss', '-H', '-lntp', 'sport = :7000'), seconds=60)
    run('systemd-run', '--unit=guard-behavior-frpc', str(frp / 'frpc'), '-c', str(work / 'frpc.toml'))
    wait_for(lambda: 'frps' in output('ss', '-H', '-lntp', 'sport = :22004'))
    run('env', 'FRP_GUARD_CONFIG_USER=guardbehavior', 'apt', '-y', 'install', str(old))
    home = Path('/home/guardbehavior/.frp-ssh-guard')
    settings = home / 'settings.conf'
    settings.write_text(settings.read_text()
                        .replace('PROTECTED_PORTS=""', 'PROTECTED_PORTS="22001-22004"')
                        .replace('PER_IP_RATE=2', 'PER_IP_RATE=100').replace('PER_IP_BURST=40', 'PER_IP_BURST=100')
                        .replace('GLOBAL_RATE=30', 'GLOBAL_RATE=1000').replace('GLOBAL_BURST=20', 'GLOBAL_BURST=1000'))
    guard('enable')
    assert 'set synseen4' not in output('nft', 'list', 'table', 'inet', TABLE)

    # The package upgrade refreshes the active guard by itself, with the new rules on.
    installed = run('apt', '-y', 'install', str(new)).stdout
    assert 'Upgrade applied automatically' in installed and 'SSH_SLOW_BEHAVIOR=on' in installed
    text = settings.read_text()
    assert 'SSH_SLOW_BEHAVIOR=on\n' in text and 'LEARN_USERS=on\n' in text, text
    rules = output('nft', 'list', 'table', 'inet', TABLE)
    assert 'set synseen4' in rules and 'set known4' in rules and '"22001 observe v4"' in rules
    assert 'Behavior rules: on' in guard('status')
    print('PASS: upgrade turns the rules and learning on without a manual reload', flush=True)

    run('ip', 'netns', 'add', 'guard-client')
    run('ip', 'link', 'add', 'guard-host', 'type', 'veth', 'peer', 'name', 'guard-peer')
    run('ip', 'link', 'set', 'guard-peer', 'netns', 'guard-client')
    run('ip', 'addr', 'add', '198.51.100.1/24', 'dev', 'guard-host')
    run('ip', 'link', 'set', 'guard-host', 'up')
    for suffix in (31, 32, 33, 34):
        run('ip', '-n', 'guard-client', 'addr', 'add', f'198.51.100.{suffix}/24', 'dev', 'guard-peer')
    run('ip', '-n', 'guard-client', 'link', 'set', 'guard-peer', 'up')
    run('ip', '-n', 'guard-client', 'link', 'set', 'lo', 'up')
    settings.write_text(settings.read_text().replace('SSH_BEHAVIOR_PAUSE=2h', 'SSH_BEHAVIOR_PAUSE=30m')
                        .replace('SSH_BEHAVIOR_RULES="4p:2h 3p:6h 50c:12h"', 'SSH_BEHAVIOR_RULES="2p:15m"'))
    guard('check')
    guard('reload')
    assert '"22001 observe v4"' in output('nft', 'list', 'table', 'inet', TABLE)

    # A session that delivered more than 32 KiB proves a login; that pair is no longer counted.
    client('import socket, time; s=socket.socket(); s.bind(("198.51.100.32",0)); s.connect(("198.51.100.1",22004))\n'
           'data=b""\nwhile len(data) < 40000: data += s.recv(65536)\ntime.sleep(150)')
    wait_for(lambda: '198.51.100.32 22004' in elements('known4'), seconds=30)
    attempt('198.51.100.32', 22004)
    assert '198.51.100.32 22004' not in elements('count4')
    assert 'known-user source=198.51.100.32 ports=22004' in (home / 'frp-ssh-guard.log').read_text()
    print('PASS: a session with real output makes a known user who is no longer counted', flush=True)

    # Resent SYNs count once: drop the SYN-ACKs so the client kernel retransmits.
    run('ip', 'netns', 'exec', 'guard-client', 'nft', 'add table inet guardtest; '
        'add chain inet guardtest in { type filter hook input priority 0; }; '
        'add rule inet guardtest in tcp sport 22003 tcp flags & (syn | ack) == syn | ack drop')
    attempt('198.51.100.33', 22003, timeout=4)  # SYN at 0s, resent at about 1s and 3s
    run('ip', 'netns', 'exec', 'guard-client', 'nft', 'delete table inet guardtest')
    assert elements('count4')['198.51.100.33 22003']['counter']['packets'] == 1
    print('PASS: a SYN resent with the same source port and sequence counts once', flush=True)

    rotate_until_banned('198.51.100.31', 'ban4')
    log = (home / 'frp-ssh-guard.log').read_text()
    assert 'ban source=198.51.100.31 ports=all reason=restless-ports limit=2ports/15m,pause=30m' in log, log
    print('PASS: shared jails ban a restless two-port source on all ports', flush=True)

    settings.write_text(settings.read_text().replace('JAIL_PER_PORT=off', 'JAIL_PER_PORT=on'))
    guard('check')
    guard('reload')
    rotate_until_banned('198.51.100.34', 'wideban4')
    assert '198.51.100.34 22003' not in elements('ban4')  # one address-wide ban, not one per port
    assert not vm.connect('198.51.100.34', 22003)  # also a port it never touched
    assert '198.51.100.34 all source=runtime' in (home / 'blocklist.conf').read_text()
    print('PASS: per-port jails ban a rotating source on all ports through wideban4', flush=True)
    guard('disable')
    run('ip', 'netns', 'del', 'guard-client')


if __name__ == '__main__':
    main()
