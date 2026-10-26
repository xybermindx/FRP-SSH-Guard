#!/usr/bin/env python3
"""Disposable systemd VM only: upgrade actual jails, then test real SSH learning.

FRP_GUARD_DISPOSABLE=1 python3 tests/vm-unified-lists.py OLD.deb NEW.deb FRP_DIR off|on
Requires a purged package and an unused /home/guardmigration account.
"""
import importlib.util
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('vm_acceptance', Path(__file__).with_name('vm-acceptance.py'))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
run, output, guard, wait_for, jail, properties = vm.run, vm.output, vm.guard, vm.wait_for, vm.jail, vm.properties


def main():
    assert os.environ.get('FRP_GUARD_DISPOSABLE') == '1' and os.geteuid() == 0
    old, new, frp = [Path(p).resolve() for p in sys.argv[1:4]]
    mode = sys.argv[4]
    assert mode in ('off', 'on')
    assert run('dpkg-query', '-W', 'frp-ssh-guard', check=False).returncode != 0
    work = Path('/tmp/unified-test')
    work.mkdir(exist_ok=True)
    (work / 'frps.toml').write_text('bindPort = 7000\n')
    (work / 'frpc.toml').write_text('serverAddr = "127.0.0.1"\nserverPort = 7000\n' + ''.join(
        f'[[proxies]]\nname = "example-tunnel-{p}"\ntype = "tcp"\nlocalIP = "127.0.0.1"\nlocalPort = 22\nremotePort = {p}\n'
        for p in (22001, 22003)))
    run('systemd-run', '--unit=guard-test-frps', str(frp / 'frps'), '-c', str(work / 'frps.toml'))
    wait_for(lambda: 'frps' in output('ss', '-H', '-lntp', 'sport = :7000'), seconds=60)
    run('systemd-run', '--unit=guard-test-frpc', str(frp / 'frpc'), '-c', str(work / 'frpc.toml'))
    wait_for(lambda: 'frps' in output('ss', '-H', '-lntp', 'sport = :22003'))
    run('useradd', '-m', 'guardmigration')
    run('env', 'FRP_GUARD_CONFIG_USER=guardmigration', 'apt', '-y', 'install', str(old))
    home = Path('/home/guardmigration/.frp-ssh-guard')
    settings = home / 'settings.conf'
    settings.write_text('# retain this customization\nPROTECTED_PORTS="22001,22003"\nPROTECT_SERVER_SSH=on\n'
                        f'JAIL_PER_PORT={mode}\nLOGIN_USERS=root\nLEARN_TIMEOUT=1h\n'
                        'PER_IP_RATE=1000\nPER_IP_BURST=1000\nGLOBAL_RATE=2000\nGLOBAL_BURST=2000\n')
    (home / 'whitelist.conf').write_text('# preserve manual comment\n203.0.113.20 22\n')
    (home / 'blocklist.conf').write_text('# preserve block comment\n203.0.113.30 22001\n')
    guard('enable')
    guard('ban', '198.51.100.88', '19m')
    table = 'frp_ssh_persistent_guard'
    concat = ' . 22' if mode == 'on' else ''
    run('nft', 'add', 'element', 'inet', table, 'hardban4', '{ 198.51.100.87' + concat + ' timeout 23m }')
    run('nft', 'add', 'element', 'inet', table, 'learned4', '{ 198.51.100.89 timeout 13m }')
    state = Path('/var/lib/frp-ssh-guard/lists')
    (state / 'learned.conf').write_text('198.51.100.89\n')
    (state / 'hardban.conf').write_text('198.51.100.87' + (' 22' if mode == 'on' else '') + '\n')
    timers = {}
    for unit in ('log', 'strike'):
        directory = Path('/etc/systemd/system/frp-ssh-guard-' + unit + '.timer.d')
        directory.mkdir(exist_ok=True)
        (directory / 'custom.conf').write_text('[Timer]\nOnBootSec=\nOnUnitActiveSec=\nOnActiveSec=47min\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'restart', 'frp-ssh-guard-log.timer', 'frp-ssh-guard-strike.timer')
    for unit in ('log', 'strike'):
        timers[unit] = properties('frp-ssh-guard-' + unit + '.timer', ['ActiveEnterTimestampMonotonic', 'NextElapseUSecMonotonic'])
    service = properties('frp-ssh-guard.service', ['InvocationID', 'ActiveEnterTimestampMonotonic'])
    before = {name: jail(name) for name in ('ban4', 'hardban4', 'learned4')}
    settings_before = settings.read_text()
    accepted_before = Path('/var/lib/frp-ssh-guard/applied.conf').read_bytes()
    started = time.monotonic()
    run('apt', '-y', 'install', str(new))
    assert output('dpkg-query', '-W', '-f=${Version}', 'frp-ssh-guard') == output('dpkg-deb', '-f', str(new), 'Version')
    for line in settings_before.splitlines():
        assert line in settings.read_text().splitlines()
    assert Path('/var/lib/frp-ssh-guard/applied.conf').read_bytes() == accepted_before
    assert service == properties('frp-ssh-guard.service', list(service))
    for unit, expected in timers.items():
        assert expected == properties('frp-ssh-guard-' + unit + '.timer', list(expected))
    for name, values in before.items():
        for key, ttl in values.items():
            after = jail(name)[key]
            assert ttl - (time.monotonic() - started) - 3 <= after <= ttl, (name, key, ttl, after)
    assert '198.51.100.88 source=runtime until=' in (home / 'blocklist.conf').read_text()
    assert '198.51.100.87 source=strike until=' in (home / 'blocklist.conf').read_text()
    assert '198.51.100.89 source=learned until=' in (home / 'whitelist.conf').read_text()
    assert '# preserve manual comment' in (home / 'whitelist.conf').read_text()
    assert '# preserve block comment' in (home / 'blocklist.conf').read_text()
    assert (home / 'blocklist.conf').stat().st_uid == int(output('id', '-u', 'guardmigration'))
    assert (home / 'blocklist.conf').stat().st_mode & 0o777 == 0o600
    guard('apply')  # also exercises extending an older active table without replacement
    for unit, expected in timers.items():
        assert expected == properties('frp-ssh-guard-' + unit + '.timer', list(expected))
    assert jail()['198.51.100.88' + (' 22' if mode == 'on' else '')] <= before['ban4']['198.51.100.88' + (' 22' if mode == 'on' else '')]
    print('PASS: automatic jail migration, comments, owner, scopes, TTLs, accepted policy and timer deadlines', flush=True)

    # Manual network ranges can overlap imported automatic host bans.
    guard('block', '198.51.100.0/24', '--all')
    guard('unblock', '198.51.100.0/24')
    # Explicit reload starts the updated long-running monitors, retaining exported bans.
    guard('reload')
    restored = 'saved_ban_pp4' if mode == 'on' else 'saved_ban4'
    assert '198.51.100.88' + (' 22' if mode == 'on' else '') in jail(restored)
    guard('unban', '198.51.100.88')
    assert '198.51.100.88' not in (home / 'blocklist.conf').read_text()
    assert all(not key.startswith('198.51.100.88') for key in jail(restored))

    run('ip', 'netns', 'add', 'guard-client')
    run('ip', 'link', 'add', 'guard-host', 'type', 'veth', 'peer', 'name', 'guard-peer')
    run('ip', 'link', 'set', 'guard-peer', 'netns', 'guard-client')
    run('ip', 'addr', 'add', '198.51.100.1/24', 'dev', 'guard-host')
    run('ip', 'link', 'set', 'guard-host', 'up')
    run('ip', '-n', 'guard-client', 'addr', 'add', '198.51.100.2/24', 'dev', 'guard-peer')
    run('ip', '-n', 'guard-client', 'link', 'set', 'guard-peer', 'up')
    run('ip', '-n', 'guard-client', 'link', 'set', 'lo', 'up')
    key = work / 'login-key'
    run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'disposable-test', '-f', str(key))
    authorized = Path('/root/.ssh/authorized_keys')
    with authorized.open('a') as stream:
        stream.write(key.with_suffix('.pub').read_text())
    def login():
        run('ip', 'netns', 'exec', 'guard-client', 'ssh', '-i', str(key), '-b', '198.51.100.2',
            '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'ConnectTimeout=5', 'root@198.51.100.1', 'true')
    def learned_deadline():
        for line in (home / 'whitelist.conf').read_text().splitlines():
            if line.startswith('198.51.100.2 '):
                return line.split('until=')[1].split()[0]
        return ''
    first_login = int(time.time())
    login()
    expected = datetime.datetime.fromtimestamp(first_login + 3600, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    wait_for(lambda: learned_deadline() >= expected, seconds=60)
    wait_for(lambda: '198.51.100.2' in jail('learned4'), seconds=30)
    deadline = learned_deadline()
    time.sleep(3)
    login()
    wait_for(lambda: learned_deadline() > deadline, seconds=30)
    guard('block', '198.51.100.2', '--all')
    assert vm.connect('198.51.100.2', 22)
    assert vm.connect('198.51.100.2', 22001)
    for _ in range(4):
        run('ip', 'netns', 'exec', 'guard-client', 'ssh', '-b', '198.51.100.2', '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=3',
            'missing-example-account@198.51.100.1', 'true', check=False)
    time.sleep(2)
    assert all(not key.startswith('198.51.100.2') for key in jail())
    guard('forget', '198.51.100.2')
    assert not vm.connect('198.51.100.2', 22)
    assert not vm.connect('198.51.100.2', 22001)
    guard('allow', '198.51.100.2', '22')
    assert vm.connect('198.51.100.2', 22)
    assert not vm.connect('198.51.100.2', 22001)
    print('PASS: actual local SSH learning/refresh, native-22 whitelist precedence and port scope', flush=True)
    guard('ban', '203.0.113.40', '4s')
    wait_for(lambda: all(not key.startswith('203.0.113.40') for key in jail()), seconds=12)
    guard('apply')
    assert '203.0.113.40' not in (home / 'blocklist.conf').read_text()
    assert all(not key.startswith('203.0.113.40') for key in jail(restored))
    with (home / 'blocklist.conf').open('a') as stream:
        stream.write('\n[22]\n203.0.113.50 tier=1\n[22001]\n203.0.113.51 forever\n')
    guard('apply')
    tier_line = next(line for line in (home / 'blocklist.conf').read_text().splitlines() if line.startswith('203.0.113.50 '))
    assert 'tier=1 until=' in tier_line
    guard('apply')
    assert tier_line in (home / 'blocklist.conf').read_text().splitlines()
    assert '203.0.113.50 22' in jail('block_pp4')
    assert '203.0.113.51 22001' in jail('block_pp4')
    print('ALL UNIFIED-LIST VM CHECKS PASSED: JAIL_PER_PORT=' + mode, flush=True)


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout, error.stderr, file=sys.stderr)
        raise
