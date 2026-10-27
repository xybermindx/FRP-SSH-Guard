#!/usr/bin/env python3
"""Disposable systemd VM only, initially without an installed guard.

FRP_GUARD_DISPOSABLE=1 python3 tests/vm-jail-modes.py OLD.deb NEW.deb FRP_DIR
Uses real FRP listeners, kernel bans and synthetic documentation addresses.
"""
import datetime
import importlib.util
import os
from pathlib import Path
import sys
import time

spec = importlib.util.spec_from_file_location('vm', Path(__file__).with_name('vm-acceptance.py'))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
run, output, guard, wait_for = vm.run, vm.output, vm.guard, vm.wait_for


def main():
    assert os.environ.get('FRP_GUARD_DISPOSABLE') == '1' and os.geteuid() == 0
    old, new, frp = [Path(p).resolve() for p in sys.argv[1:]]
    assert run('dpkg-query', '-W', 'frp-ssh-guard', check=False).returncode != 0
    run('useradd', '-m', 'guardmodes')
    work = Path('/tmp/guard-mode-test')
    work.mkdir(exist_ok=True)
    (work / 'frps.toml').write_text('bindPort = 7000\n')
    (work / 'frpc.toml').write_text('serverAddr = "127.0.0.1"\nserverPort = 7000\n' + ''.join(
        f'[[proxies]]\nname = "example-mode-{port}"\ntype = "tcp"\nlocalIP = "127.0.0.1"\nlocalPort = 22\nremotePort = {port}\n'
        for port in (22001, 22003)))
    run('systemd-run', '--unit=guard-modes-frps', str(frp / 'frps'), '-c', str(work / 'frps.toml'))
    wait_for(lambda: 'frps' in output('ss', '-H', '-lntp', 'sport = :7000'), seconds=60)
    run('systemd-run', '--unit=guard-modes-frpc', str(frp / 'frpc'), '-c', str(work / 'frpc.toml'))
    wait_for(lambda: 'frps' in output('ss', '-H', '-lntp', 'sport = :22003'))
    run('env', 'FRP_GUARD_CONFIG_USER=guardmodes', 'apt', '-y', 'install', str(old))
    home = Path('/home/guardmodes/.frp-ssh-guard')
    settings = home / 'settings.conf'
    base = ('PROTECTED_PORTS="22001,22003"\nPER_IP_RATE=1\nPER_IP_BURST=3\n'
            'GLOBAL_RATE=1000\nGLOBAL_BURST=1000\nBAN_TIMEOUT=10m\nSTRIKE_LADDER="2:10m"\n')
    settings.write_text(base + 'JAIL_PER_PORT=on\n')
    guard('enable')
    stamp = int(time.time())
    iso = lambda value: datetime.datetime.fromtimestamp(value, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    # Mixed shared/scoped runtime, strike and manual entries; exact deadlines.
    original = ('# keep mode test comments\n[all]\n'
                f'198.51.100.11 source=runtime until={iso(stamp + 600)}\n'
                f'198.51.100.14 source=strike until={iso(stamp + 600)}\n'
                '[22001]\n'
                f'198.51.100.13 source=strike until={iso(stamp + 600)}\n'
                f'2001:db8::13 source=strike until={iso(stamp + 600)}\n'
                '198.51.100.15 forever\n')
    (home / 'blocklist.conf').write_text(original)
    guard('apply')
    # An unsampled live jail must be exported before replacing the rules.
    run('nft', 'add', 'element', 'inet', 'frp_ssh_persistent_guard', 'ban4',
        '{ 198.51.100.12 . 22001 timeout 600s }')
    Path('/var/log/frp-ssh-guard/banned.log').write_text(''.join(
        f'{iso(stamp)} ban4 {ip}\n' for ip in ('198.51.100.13 22001', '198.51.100.14') for _ in range(2)))
    timers = {name: vm.properties(f'frp-ssh-guard-{name}.timer',
              ['ActiveEnterTimestampMonotonic', 'NextElapseUSecMonotonic']) for name in ('log', 'strike')}
    assert 'Upgrade applied automatically' in run('apt', '-y', 'install', str(new)).stdout
    for name, expected in timers.items():
        assert expected == vm.properties(f'frp-ssh-guard-{name}.timer', list(expected))
    run('ip', 'netns', 'add', 'guard-client')
    run('ip', 'link', 'add', 'guard-host', 'type', 'veth', 'peer', 'name', 'guard-peer')
    run('ip', 'link', 'set', 'guard-peer', 'netns', 'guard-client')
    run('ip', 'addr', 'add', '198.51.100.1/24', 'dev', 'guard-host')
    run('ip', 'link', 'set', 'guard-host', 'up')
    for suffix in (*range(11, 16), 20, 21, 22):
        run('ip', '-n', 'guard-client', 'addr', 'add', f'198.51.100.{suffix}/24', 'dev', 'guard-peer')
    run('ip', '-n', 'guard-client', 'link', 'set', 'guard-peer', 'up')
    run('ip', '-n', 'guard-client', 'link', 'set', 'lo', 'up')
    deadlines = (home / 'blocklist.conf').read_text()
    for mode, suffix in (('off', 20), ('on', 21), ('off', 22)):
        settings.write_text(base + f'JAIL_PER_PORT={mode}\n')
        guard('check')
        guard('reload')
        run('systemctl', 'start', 'frp-ssh-guard-strike.service')
        guard('apply')
        assert '198.51.100.13 all' not in Path('/var/lib/frp-ssh-guard/lists/hardban.conf').read_text()
        for ip in ('198.51.100.11', '198.51.100.14'):
            assert ip in vm.jail('saved_ban4')
            assert not vm.connect(ip, 22001) and not vm.connect(ip, 22003)
        for ip in ('198.51.100.12', '198.51.100.13'):
            assert ip + ' 22001' in vm.jail('saved_ban_pp4')
            assert ip not in vm.jail('saved_ban4')
            assert not vm.connect(ip, 22001) and vm.connect(ip, 22003)
        assert not vm.connect('198.51.100.15', 22001) and vm.connect('198.51.100.15', 22003)
        assert '2001:db8::13 22001' in vm.jail('saved_ban_pp6')
        for name in ('saved_ban4', 'saved_ban_pp4', 'saved_ban_pp6'):
            assert all(0 < ttl <= 600 for ttl in vm.jail(name).values())
        for line in deadlines.splitlines():
            if 'until=' in line:
                assert line in (home / 'blocklist.conf').read_text(), line
        # Actual new traffic must create bans using the newly selected mode.
        source = f'198.51.100.{suffix}'
        assert vm.connect(source, 22001)
        for _ in range(7):
            vm.connect(source, 22001)
        key = source + (' 22001' if mode == 'on' else '')
        assert key in vm.jail('ban4'), vm.jail('ban4')
        assert vm.connect(source, 22003) == (mode == 'on')
        print(f'PASS: mode={mode}; old scopes/deadlines unchanged; new traffic uses selected scope', flush=True)
    # Reinstall and normal service restart must also retain the mixed scopes.
    run('dpkg', '-i', str(new))
    run('systemctl', 'restart', 'frp-ssh-guard')
    assert '198.51.100.11' in vm.jail('saved_ban4')
    assert '198.51.100.12 22001' in vm.jail('saved_ban_pp4')
    assert '198.51.100.21 22001' in vm.jail('saved_ban_pp4')
    assert '198.51.100.20' in vm.jail('saved_ban4')
    print('PASS: reinstall and service restart retain mixed shared/per-port jails', flush=True)


if __name__ == '__main__':
    main()
