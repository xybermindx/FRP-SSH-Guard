#!/usr/bin/env python3
"""Destructive acceptance test: use only in a disposable systemd VM.

FRP_GUARD_DISPOSABLE=1 python3 tests/vm-acceptance.py OLD.deb NEW.deb FRP_DIRECTORY
The directory must contain real frps/frpc binaries. Only synthetic data is used.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(*args, check=True):
    return subprocess.run(args, check=check, text=True, capture_output=True)


def output(*args):
    return run(*args).stdout.strip()


def wait_for(condition, seconds=20):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if condition():
            return
        time.sleep(0.3)
    raise AssertionError('Timed out waiting for test condition')


def guard(*args):
    return output('frp-ssh-guard', *args)


def jail(name='ban4'):
    doc = json.loads(output('nft', '-j', 'list', 'set', 'inet', 'frp_ssh_persistent_guard', name))
    result = {}
    for item in doc['nftables']:
        for element in item.get('set', {}).get('elem', []):
            elem = element['elem']
            key = elem['val']
            if isinstance(key, dict):
                key = ' '.join(map(str, key['concat']))
            result[key] = elem.get('expires', 0)
    return result


def connect(ip, port):
    code = ('import socket; s=socket.socket(); s.settimeout(0.5); '
            's.bind(("' + ip + '",0)); s.connect(("198.51.100.1",' + str(port) + ')); '
            'assert s.recv(128).startswith(b"SSH-"); s.close()')
    return run('ip', 'netns', 'exec', 'guard-client', 'python3', '-c', code, check=False).returncode == 0


def properties(unit, names):
    return {name: output('systemctl', 'show', unit, '--value', '-p', name) for name in names}


def main():
    assert os.environ.get('FRP_GUARD_DISPOSABLE') == '1' and os.geteuid() == 0, 'Disposable VM and root required'
    old, new, frp = map(lambda value: Path(value).resolve(), sys.argv[1:])
    assert run('dpkg-query', '-W', 'frp-ssh-guard', check=False).returncode != 0, 'Start with a fresh VM'
    work = Path('/tmp/guard-acceptance')
    work.mkdir(exist_ok=True)
    server = work / 'frps.toml'
    server.write_text('bindPort = 7000\n')
    client = work / 'frpc.toml'
    client.write_text('serverAddr = "127.0.0.1"\nserverPort = 7000\n' + ''.join(
        f'[[proxies]]\nname = "example-ssh-{port}"\ntype = "tcp"\nlocalIP = "127.0.0.1"\nlocalPort = 22\nremotePort = {port}\n'
        for port in (22001, 22003)))
    run('systemd-run', '--unit=guard-test-frps', str(frp / 'frps'), '-c', str(server))
    wait_for(lambda: 'frps' in output('ss', '-H', '-lntp', 'sport = :7000'), seconds=60)
    run('systemd-run', '--unit=guard-test-frpc', str(frp / 'frpc'), '-c', str(client))
    wait_for(lambda: 'frps' in output('ss', '-H', '-lntp', 'sport = :22003'))
    run('apt-get', '-y', 'install', str(old))
    settings = Path('/etc/frp-ssh-guard/settings.conf')
    settings.write_text('PROTECTED_PORTS="22001,22003"\nPER_IP_RATE=9\nPER_IP_BURST=13\n'
                        'BAN_TIMEOUT=43m\nSTRIKE_LADDER="2:7h 3:2d"\n')
    lists = Path('/var/lib/frp-ssh-guard/lists')
    (lists / 'blocklist.conf').write_text('203.0.113.8\n')
    guard('enable')
    for unit, duration in [('log', '17min'), ('strike', '23min')]:
        directory = Path(f'/etc/systemd/system/frp-ssh-guard-{unit}.timer.d')
        directory.mkdir(exist_ok=True)
        (directory / 'custom.conf').write_text(f'[Timer]\nOnBootSec=\nOnBootSec=1d\nOnUnitActiveSec=\nOnUnitActiveSec={duration}\n')
        if output('dpkg-deb', '-f', str(old), 'Version') == '0.0.5':
            with (directory / 'custom.conf').open('a') as file:
                file.write('OnActiveSec=31min\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'restart', 'frp-ssh-guard-log.timer', 'frp-ssh-guard-strike.timer')
    guard('ban', '198.51.100.88', '19m')
    fail2ban = Path('/etc/fail2ban/jail.local')
    fail2ban.parent.mkdir(exist_ok=True)
    fail2ban.write_text('# unrelated local customization\n[sshd]\nbantime = 7h\n')
    files = [settings, Path('/var/lib/frp-ssh-guard/applied.conf'), lists / 'blocklist.conf', fail2ban]
    files += list(Path('/etc/systemd/system').glob('frp-ssh-guard-*.timer.d/custom.conf'))
    before = {str(path): (path.read_bytes(), path.stat().st_mode) for path in files}
    service_before = properties('frp-ssh-guard.service', ['InvocationID', 'ActiveEnterTimestampMonotonic'])
    timers_before = {unit: properties(f'frp-ssh-guard-{unit}.timer',
                     ['ActiveEnterTimestampMonotonic', 'NextElapseUSecMonotonic']) for unit in ('log', 'strike')}
    ttl_before = jail()['198.51.100.88']
    start = time.monotonic()
    run('useradd', '-m', 'guardadmin')
    sudoers = Path('/etc/sudoers.d/guard-acceptance')
    sudoers.write_text('guardadmin ALL=(ALL) NOPASSWD: ALL\n')
    sudoers.chmod(0o440)
    run('runuser', '-u', 'guardadmin', '--', 'sudo', '-n', 'apt-get', '-y', 'install', '--reinstall', str(new))
    assert guard('--version') == 'FRP-SSH-Guard 0.0.5'
    assert before == {str(path): (path.read_bytes(), path.stat().st_mode) for path in files}
    assert service_before == properties('frp-ssh-guard.service', list(service_before))
    for unit, expected in timers_before.items():
        assert expected == properties(f'frp-ssh-guard-{unit}.timer', list(expected))
    ttl_after = jail()['198.51.100.88']
    assert ttl_before - (time.monotonic() - start + 3) <= ttl_after <= ttl_before
    displayed = guard('banned')
    displayed_ttl = int(next(line.split()[-1] for line in displayed.splitlines() if '198.51.100.88' in line))
    assert 0 < ttl_after - 3 <= displayed_ttl <= ttl_after
    assert 'tcp dport 22 ' not in output('nft', 'list', 'table', 'inet', 'frp_ssh_persistent_guard')
    print('PASS: real upgrade preserves custom files, active service, timers and ban expiry', flush=True)

    home = Path('/home/guardadmin/.frp-ssh-guard')
    assert (home / 'settings.conf').read_bytes() == settings.read_bytes()
    assert (home / 'blocklist.conf').read_bytes() == (lists / 'blocklist.conf').read_bytes()
    assert (home / 'settings.conf').stat().st_mode & 0o777 == 0o600
    assert (home / 'settings.conf').stat().st_uid == int(output('id', '-u', 'guardadmin'))
    assert service_before == properties('frp-ssh-guard.service', list(service_before))
    assert 0 < jail()['198.51.100.88'] <= ttl_after
    assert output('systemctl', 'is-active', 'frp-ssh-guard-home-lists.path') == 'active'
    assert run('systemctl', 'is-active', '--quiet', 'frp-ssh-guard-lists.path', check=False).returncode != 0
    # A normal user edit must reach the firewall without CLI reload or a timer tick.
    run('runuser', '-u', 'guardadmin', '--', 'sh', '-c',
        'printf "203.0.113.99 all\\n" >> "$HOME/.frp-ssh-guard/blocklist.conf"')
    wait_for(lambda: '203.0.113.99' in output('nft', 'list', 'set', 'inet', 'frp_ssh_persistent_guard', 'manual4'))
    for unit, expected in timers_before.items():
        assert expected == properties(f'frp-ssh-guard-{unit}.timer', list(expected))
    assert 0 < jail()['198.51.100.88'] <= ttl_after
    guard('config-home', 'guardadmin')  # idempotent; no manager reload
    for unit in ('log', 'strike'):
        path = Path(f'/etc/systemd/system/frp-ssh-guard-{unit}.timer.d/custom.conf')
        path.write_text(path.read_text() + 'OnActiveSec=31min\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'restart', 'frp-ssh-guard-log.timer', 'frp-ssh-guard-strike.timer')
    before = {str(path): (path.read_bytes(), path.stat().st_mode) for path in files}
    # Reinstall as root must retain the original installing user's home.
    timers_before = {unit: properties(f'frp-ssh-guard-{unit}.timer', list(expected))
                     for unit, expected in timers_before.items()}
    run('dpkg', '-i', str(new))
    assert before == {str(path): (path.read_bytes(), path.stat().st_mode) for path in files}
    assert (home / 'settings.conf').read_bytes() == settings.read_bytes()
    for unit, expected in timers_before.items():
        assert expected == properties(f'frp-ssh-guard-{unit}.timer', list(expected))
    print('PASS: automatic sudo-user home migration, immediate file watching, and root reinstall retain policy/bans/owner/timers', flush=True)

    run('ip', 'netns', 'add', 'guard-client')
    run('ip', 'link', 'add', 'guard-host', 'type', 'veth', 'peer', 'name', 'guard-peer')
    run('ip', 'link', 'set', 'guard-peer', 'netns', 'guard-client')
    run('ip', 'addr', 'add', '198.51.100.1/24', 'dev', 'guard-host')
    run('ip', 'link', 'set', 'guard-host', 'up')
    for suffix in (2, 3, 4):
        run('ip', '-n', 'guard-client', 'addr', 'add', f'198.51.100.{suffix}/24', 'dev', 'guard-peer')
    run('ip', '-n', 'guard-client', 'link', 'set', 'guard-peer', 'up')
    run('ip', '-n', 'guard-client', 'link', 'set', 'lo', 'up')
    settings = home / 'settings.conf'
    for scope in ('off', 'on'):
        settings.write_text('PROTECTED_PORTS="22001,22003"\nPROTECT_SERVER_SSH=on\n'
                            f'JAIL_PER_PORT={scope}\nPER_IP_RATE=1\nPER_IP_BURST=3\n'
                            'GLOBAL_RATE=1000\nGLOBAL_BURST=1000\nBAN_TIMEOUT=5m\n')
        guard('reload')
        assert connect('198.51.100.2', 22001), 'Real FRP tunnel must forward SSH'
        for _ in range(8):
            connect('198.51.100.2', 22001)
        expected = '198.51.100.2' + (' 22001' if scope == 'on' else '')
        assert expected in jail(), jail()
        assert connect('198.51.100.2', 22003) == (scope == 'on')
        assert connect('198.51.100.2', 22) == (scope == 'on')
        for _ in range(3):
            run('ip', 'netns', 'exec', 'guard-client', 'ssh', '-b', '198.51.100.3',
                '-o', 'BatchMode=yes', '-o', 'ConnectionAttempts=1', '-o', 'ConnectTimeout=3',
                '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                'missing-guard-test@198.51.100.1', 'true', check=False)
        expected = '198.51.100.3' + (' 22' if scope == 'on' else '')
        wait_for(lambda: expected in jail())
        journal = output('journalctl', '-u', 'frp-ssh-guard-auth.service', '--no-pager')
        assert 'SSH authentication threshold reached; guard ban applied.' in journal
        assert connect('198.51.100.3', 22003) == (scope == 'on')
        print(f'PASS: real FRP SYN bans and local invalid-user SSH bans, JAIL_PER_PORT={scope}', flush=True)

    before = jail()
    guard('block', '198.51.100.4', '--ports', '22003', '--for', '15s')
    expiry = (home / 'blocklist.conf').read_text()
    assert 'until=' in expiry
    assert not connect('198.51.100.4', 22003)
    assert connect('198.51.100.4', 22001)
    guard('apply')
    assert (home / 'blocklist.conf').read_text() == expiry
    for key, ttl in before.items():
        assert 0 < jail()[key] <= ttl
    wait_for(lambda: connect('198.51.100.4', 22003), seconds=25)
    guard('block', '198.51.100.4', '--all')
    assert not connect('198.51.100.4', 22001)
    assert not connect('198.51.100.4', 22003)
    assert not connect('198.51.100.4', 22)
    print('PASS: scoped expiry and permanent all-port manual blocks; live auto bans retained', flush=True)
    run('systemd-analyze', 'verify', '/usr/lib/systemd/system/frp-ssh-guard-auth.service')
    print('ALL VM ACCEPTANCE CHECKS PASSED', flush=True)


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout, error.stderr, file=sys.stderr)
        raise
