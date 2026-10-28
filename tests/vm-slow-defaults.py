#!/usr/bin/env python3
"""Disposable systemd VM only, with no installed guard or existing fixtures.

FRP_GUARD_DISPOSABLE=1 python3 tests/vm-slow-defaults.py NEW.deb
Uses real sshd failures and nftables; only invented identities and addresses.
"""
import importlib.util
import os
from pathlib import Path
import sqlite3
import sys

spec = importlib.util.spec_from_file_location('vm', Path(__file__).with_name('vm-acceptance.py'))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


def main():
    assert os.environ.get('FRP_GUARD_DISPOSABLE') == '1' and os.geteuid() == 0
    assert vm.run('dpkg-query', '-W', 'frp-ssh-guard', check=False).returncode != 0
    package = str(Path(sys.argv[1]).resolve())
    vm.run('useradd', '-m', 'guardslowfresh')
    vm.run('env', 'FRP_GUARD_CONFIG_USER=guardslowfresh', 'apt', '-y', 'install', package)
    home = Path('/home/guardslowfresh/.frp-ssh-guard')
    settings = home / 'settings.conf'
    fresh = settings.read_text()
    assert 'SSH_SLOW_PROTECTION=on\n' in fresh
    assert 'SSH_SLOW_MODE' not in fresh
    assert 'PROTECT_SERVER_SSH=off\n' in fresh
    assert 'LOGIN_USERS=""\n' in fresh
    assert vm.run('systemctl', 'is-active', '--quiet', 'frp-ssh-guard.service', check=False).returncode != 0
    # Keep the shipped slow switch/threshold; isolate it from fast detection.
    settings.write_text(fresh.replace('PROTECT_SERVER_SSH=off', 'PROTECT_SERVER_SSH=on')
                        .replace('SSH_AUTH_FAILURES=5', 'SSH_AUTH_FAILURES=100')
                        .replace('SSH_INVALID_USER_FAILURES=3', 'SSH_INVALID_USER_FAILURES=100'))
    vm.guard('enable')
    assert 'Slow SSH protection: on' in vm.guard('doctor')
    vm.run('ip', 'netns', 'add', 'guard-slow-client')
    vm.run('ip', 'link', 'add', 'guard-slow-host', 'type', 'veth', 'peer', 'name', 'guard-slow-peer')
    vm.run('ip', 'link', 'set', 'guard-slow-peer', 'netns', 'guard-slow-client')
    vm.run('ip', 'addr', 'add', '198.51.100.1/24', 'dev', 'guard-slow-host')
    vm.run('ip', 'link', 'set', 'guard-slow-host', 'up')
    vm.run('ip', '-n', 'guard-slow-client', 'addr', 'add', '198.51.100.77/24', 'dev', 'guard-slow-peer')
    vm.run('ip', '-n', 'guard-slow-client', 'link', 'set', 'guard-slow-peer', 'up')
    database = Path('/var/lib/frp-ssh-guard/observations/events.sqlite3')

    def count(kind):
        with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
            return db.execute('SELECT count(*) FROM events WHERE kind=? AND ip=?',
                              (kind, '198.51.100.77')).fetchone()[0]

    for index in range(20):
        vm.run('ip', 'netns', 'exec', 'guard-slow-client', 'ssh', '-b', '198.51.100.77',
               '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
               '-o', 'UserKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=3',
               'missing-example-account@198.51.100.1', 'true', check=False)
        vm.wait_for(lambda: count('auth-failure') >= index + 1, seconds=30)
        if index < 19:
            assert count('ban') == 0
    vm.wait_for(lambda: count('ban') == 1, seconds=30)
    assert count('slow-threshold') == 1
    assert any(key.startswith('198.51.100.77') for key in vm.jail())
    vm.run('dpkg', '-i', package)
    assert 'SSH_SLOW_PROTECTION=on\n' in settings.read_text()
    assert count('ban') == 1
    assert 'reason=slow-failed-logins' in (home / 'frp-ssh-guard.log').read_text()
    print('PASS: fresh default bans at 20 real sshd failures; no earlier ban; reinstall preserves switch and offense count', flush=True)
    vm.guard('disable')
    vm.run('ip', 'netns', 'del', 'guard-slow-client')


if __name__ == '__main__':
    main()
