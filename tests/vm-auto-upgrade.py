#!/usr/bin/env python3
"""Disposable systemd VM only; never run against a production guard.

FRP_GUARD_DISPOSABLE=1 python3 tests/vm-auto-upgrade.py OLD.deb NEW.deb FRP_DIR off|on
Requires no installed guard and an unused guardupgradeoff/guardupgradeon account.
"""
import importlib.util
import os
from pathlib import Path
import sys
import time

spec = importlib.util.spec_from_file_location('vm', Path(__file__).with_name('vm-acceptance.py'))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
run, output, guard, wait_for, properties = vm.run, vm.output, vm.guard, vm.wait_for, vm.properties


def bans():
    result = {}
    for name in ('ban4', 'ban6', 'hardban4', 'hardban6', 'saved_ban4', 'saved_ban6', 'saved_ban_pp4', 'saved_ban_pp6'):
        for key, ttl in vm.jail(name).items():
            result[key] = max(result.get(key, 0), ttl)
    return result


def main():
    assert os.environ.get('FRP_GUARD_DISPOSABLE') == '1' and os.geteuid() == 0
    old, new, frp = [Path(p).resolve() for p in sys.argv[1:4]]
    mode = sys.argv[4]
    assert mode in ('off', 'on')
    assert run('dpkg-query', '-W', 'frp-ssh-guard', check=False).returncode != 0
    user = 'guardupgrade' + mode
    run('useradd', '-m', user)
    work = Path('/tmp/auto-upgrade-test')
    work.mkdir(exist_ok=True)
    (work / 'frps.toml').write_text('bindPort = 7000\n')
    (work / 'frpc.toml').write_text('serverAddr = "127.0.0.1"\nserverPort = 7000\n' + ''.join(
        f'[[proxies]]\nname = "example-upgrade-{port}"\ntype = "tcp"\nlocalIP = "127.0.0.1"\nlocalPort = 22\nremotePort = {port}\n'
        for port in (22001, 22003)))
    run('systemd-run', '--unit=guard-upgrade-frps', str(frp / 'frps'), '-c', str(work / 'frps.toml'))
    wait_for(lambda: 'frps' in output('ss', '-H', '-lntp', 'sport = :7000'), seconds=60)
    run('systemd-run', '--unit=guard-upgrade-frpc', str(frp / 'frpc'), '-c', str(work / 'frpc.toml'))
    wait_for(lambda: 'frps' in output('ss', '-H', '-lntp', 'sport = :22003'))
    run('env', 'FRP_GUARD_CONFIG_USER=' + user, 'apt', '-y', 'install', str(old))
    home = Path('/home') / user / '.frp-ssh-guard'
    settings = home / 'settings.conf'
    valid = ('# Custom settings retained by automatic upgrades\nPROTECTED_PORTS="22001,22003"\n'
             f'PROTECT_SERVER_SSH=on\nJAIL_PER_PORT={mode}\nLOGIN_USERS=root\n'
             'BAN_TIMEOUT=43m\nPER_IP_RATE=1000\nPER_IP_BURST=1000\n')
    settings.write_text(valid)
    guard('enable')
    wait_for(lambda: output('systemctl', 'show', 'frp-ssh-guard-auth', '-p', 'MainPID', '--value') != '0')
    for name in ('log', 'strike'):
        dropin = Path(f'/etc/systemd/system/frp-ssh-guard-{name}.timer.d')
        dropin.mkdir(exist_ok=True)
        (dropin / 'custom.conf').write_text('[Timer]\nOnBootSec=\nOnUnitActiveSec=\nOnActiveSec=47min\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'restart', 'frp-ssh-guard-log.timer', 'frp-ssh-guard-strike.timer')
    guard('ban', '198.51.100.88', '19m')
    guard('block', '203.0.113.30', '--ports', '22001', '--for', '23m')
    guard('allow', '2001:db8::20', '22003')
    original_policy = Path('/var/lib/frp-ssh-guard/applied.conf').read_text()
    settings.write_text(valid + '\nPER_IP_RATE=invalid\n')
    pending = settings.read_bytes()
    service = properties('frp-ssh-guard.service', ['InvocationID', 'ActiveEnterTimestampMonotonic'])
    timers = {name: properties(f'frp-ssh-guard-{name}.timer', ['ActiveEnterTimestampMonotonic', 'NextElapseUSecMonotonic'])
              for name in ('log', 'strike')}
    pids = {name: output('systemctl', 'show', f'frp-ssh-guard-{name}', '-p', 'MainPID', '--value') for name in ('auth', 'learn')}
    before = bans()
    assert before
    started = time.monotonic()
    installed = run('apt', '-y', 'install', str(new))
    assert 'Upgrade applied automatically' in installed.stdout, installed.stdout + installed.stderr
    for line in pending.decode().splitlines():
        assert line in settings.read_text().splitlines(), line
    merged_settings = settings.read_bytes()
    after_policy = Path('/var/lib/frp-ssh-guard/applied.conf').read_text()
    for line in original_policy.splitlines():
        if not line.startswith('OBSERVABILITY_VERSION='):
            assert line in after_policy.splitlines(), line
    assert 'OBSERVABILITY_VERSION=1' in after_policy
    assert 'Pending edits: yes' in guard('status')
    assert service == properties('frp-ssh-guard.service', list(service))
    for name, before_pid in pids.items():
        after_pid = output('systemctl', 'show', f'frp-ssh-guard-{name}', '-p', 'MainPID', '--value')
        assert after_pid != '0' and after_pid != before_pid, (name, before_pid, after_pid)
    for name, expected in timers.items():
        assert expected == properties(f'frp-ssh-guard-{name}.timer', list(expected))
    after = bans()
    for key, ttl in before.items():
        assert key in after and ttl - (time.monotonic() - started) - 5 <= after[key] <= ttl, (key, ttl, after)
    assert '203.0.113.30' in output('nft', 'list', 'set', 'inet', 'frp_ssh_persistent_guard', 'block_pp4')
    assert '2001:db8::20' in output('nft', 'list', 'set', 'inet', 'frp_ssh_persistent_guard', 'allow_pp6')
    assert 'Live native SSH ban rules (IPv4/IPv6): present' in guard('doctor')
    print(f'PASS ({mode}): ordinary APT upgrade refreshed both monitor PIDs, preserved policy/pending edits, scoped bans/expiry, timers and boot state', flush=True)

    # Reinstall is idempotent for user policy and does not renew ban lifetimes.
    before = bans()
    run('dpkg', '-i', str(new))
    assert settings.read_bytes() == merged_settings
    for key, ttl in before.items():
        assert 0 < bans()[key] <= ttl
    guard('disable')
    run('dpkg', '-i', str(new))
    assert run('systemctl', 'is-active', '--quiet', 'frp-ssh-guard.service', check=False).returncode != 0
    assert run('systemctl', 'is-enabled', '--quiet', 'frp-ssh-guard.service', check=False).returncode != 0
    assert run('nft', 'list', 'table', 'inet', 'frp_ssh_persistent_guard', check=False).returncode != 0
    print(f'PASS ({mode}): reinstall preserves deadlines; a disabled installation remains disabled', flush=True)

    settings.write_text(valid)
    guard('trial')
    trial = properties('frp-ssh-guard-trial.timer', ['NextElapseUSecMonotonic', 'ActiveEnterTimestampMonotonic'])
    run('dpkg', '-i', str(new))
    assert Path('/run/frp-ssh-guard-trial.pending').exists()
    assert trial == properties('frp-ssh-guard-trial.timer', list(trial))
    assert run('systemctl', 'is-enabled', '--quiet', 'frp-ssh-guard.service', check=False).returncode != 0
    guard('keep')
    guard('ban', '198.51.100.88', '19m')
    assert output('systemctl', 'is-enabled', 'frp-ssh-guard.service') == 'enabled'
    print(f'PASS ({mode}): active trial refresh retains expiry and stays temporary; keep enables reboot restoration', flush=True)


if __name__ == '__main__':
    main()
