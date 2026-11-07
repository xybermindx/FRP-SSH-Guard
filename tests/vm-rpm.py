#!/usr/bin/env python3
"""Disposable RHEL-family VM only (for example Rocky 9), without an installed guard.

FRP_GUARD_DISPOSABLE=1 python3 tests/vm-rpm.py NEW.rpm FRP_DIR
SELinux must be enforcing and firewalld active. Uses real frps/frpc, nftables and
synthetic documentation addresses only.
"""
import importlib.util
import os
from pathlib import Path
import sys
import time

spec = importlib.util.spec_from_file_location('vm', Path(__file__).with_name('vm-acceptance.py'))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
run, output, guard, wait_for = vm.run, vm.output, vm.guard, vm.wait_for
TABLE = 'frp_ssh_persistent_guard'


def table_present():
    return run('nft', 'list', 'table', 'inet', TABLE, check=False).returncode == 0


def main():
    assert os.environ.get('FRP_GUARD_DISPOSABLE') == '1' and os.geteuid() == 0
    package, frp = [Path(p).resolve() for p in sys.argv[1:]]
    assert run('rpm', '-q', 'frp-ssh-guard', check=False).returncode != 0
    assert output('getenforce') == 'Enforcing', 'SELinux must be enforcing'
    run('systemctl', 'enable', '--now', 'firewalld')
    run('useradd', '-m', 'guardrpm')
    work = Path('/tmp/guard-rpm-test')
    work.mkdir(exist_ok=True)
    (work / 'frps.toml').write_text('bindPort = 7000\n')
    (work / 'frpc.toml').write_text('serverAddr = "127.0.0.1"\nserverPort = 7000\n' + ''.join(
        f'[[proxies]]\nname = "example-rpm-{port}"\ntype = "tcp"\nlocalIP = "127.0.0.1"\nlocalPort = 22\nremotePort = {port}\n'
        for port in (22001, 22003)))
    for port in (22001, 22003):
        run('firewall-cmd', '--add-port', f'{port}/tcp')
    run('systemd-run', '--unit=guard-rpm-frps', str(frp / 'frps'), '-c', str(work / 'frps.toml'))
    wait_for(lambda: 'frps' in output('ss', '-H', '-lntp', 'sport = :7000'), seconds=60)
    run('systemd-run', '--unit=guard-rpm-frpc', str(frp / 'frpc'), '-c', str(work / 'frpc.toml'))
    wait_for(lambda: 'frps' in output('ss', '-H', '-lntp', 'sport = :22003'))
    started = time.strftime('%Y-%m-%d %H:%M:%S')
    run('env', 'FRP_GUARD_CONFIG_USER=guardrpm', 'dnf', 'install', '-y', str(package))
    settings = Path('/home/guardrpm/.frp-ssh-guard/settings.conf')
    settings.write_text(settings.read_text().replace('PROTECTED_PORTS=""', 'PROTECTED_PORTS="22001,22003"')
                        .replace('PER_IP_BURST=40', 'PER_IP_BURST=3').replace('PER_IP_RATE=2', 'PER_IP_RATE=1'))
    guard('check')
    guard('enable')
    assert table_present()
    for unit in ('frp-ssh-guard.service', 'frp-ssh-guard-auth.service', 'frp-ssh-guard-learn.service',
                 'frp-ssh-guard-log.timer', 'frp-ssh-guard-strike.timer', 'frp-ssh-guard-lists.path'):
        assert run('systemctl', 'is-active', '--quiet', unit, check=False).returncode == 0, unit
    print('PASS: rpm install and enable under SELinux enforcing with firewalld', flush=True)

    run('ip', 'netns', 'add', 'guard-client')
    run('ip', 'link', 'add', 'guard-host', 'type', 'veth', 'peer', 'name', 'guard-peer')
    run('ip', 'link', 'set', 'guard-peer', 'netns', 'guard-client')
    run('ip', 'addr', 'add', '198.51.100.1/24', 'dev', 'guard-host')
    run('ip', 'link', 'set', 'guard-host', 'up')
    run('ip', '-n', 'guard-client', 'addr', 'add', '198.51.100.41/24', 'dev', 'guard-peer')
    run('ip', '-n', 'guard-client', 'link', 'set', 'guard-peer', 'up')
    run('firewall-cmd', '--zone=trusted', '--add-interface=guard-host')
    for _ in range(8):
        vm.connect('198.51.100.41', 22001)
    wait_for(lambda: any(key.startswith('198.51.100.41') for key in vm.jail()), seconds=90)
    assert 'reason=connection-rate' in Path('/home/guardrpm/.frp-ssh-guard/frp-ssh-guard.log').read_text()
    print('PASS: a real burst is banned and logged', flush=True)

    run('firewall-cmd', '--reload')
    wait_for(table_present, seconds=90)
    run('systemctl', 'restart', 'nftables', check=False)
    wait_for(table_present, seconds=150)  # missing-table recovery reapplies it
    print('PASS: the guard table survives a firewalld reload and returns after an nftables restart', flush=True)

    denials = run('ausearch', '-m', 'AVC', '-ts', started, check=False).stdout
    assert 'frp-ssh-guard' not in denials and 'frp_ssh' not in denials, denials
    print('PASS: no SELinux denials for the guard', flush=True)

    before = settings.read_text()
    run('dnf', 'reinstall', '-y', str(package))
    assert settings.read_text() == before and table_present()
    assert run('systemctl', 'is-active', '--quiet', 'frp-ssh-guard.service', check=False).returncode == 0
    run('dnf', 'remove', '-y', 'frp-ssh-guard')
    assert not table_present() and settings.exists()
    print('PASS: reinstall keeps protection running; erase removes the table and keeps settings', flush=True)
    run('ip', 'netns', 'del', 'guard-client')


if __name__ == '__main__':
    main()
