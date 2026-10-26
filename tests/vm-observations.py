#!/usr/bin/env python3
"""Disposable VM continuation after vm-unified-lists.py; real sshd and nftables."""
import importlib.util
import os
from pathlib import Path
import re
import sqlite3
import sys
import time

spec = importlib.util.spec_from_file_location('vm', Path(__file__).with_name('vm-acceptance.py'))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
run, guard, wait_for = vm.run, vm.guard, vm.wait_for


def check_reban():
    assert os.environ.get('FRP_GUARD_DISPOSABLE') == '1' and os.geteuid() == 0
    ip = '198.51.100.10'
    path = Path('/home/guardmigration/.frp-ssh-guard/blocklist.conf')
    def count():
        with sqlite3.connect('file:/var/lib/frp-ssh-guard/observations/events.sqlite3?mode=ro', uri=True) as db:
            return db.execute("SELECT count(*) FROM events WHERE kind='ban' AND ip=?", (ip,)).fetchone()[0]
    def jailed():
        return [key for name in ('ban4', 'saved_ban4', 'saved_ban_pp4', 'hardban4') for key in vm.jail(name)]
    previous = count()
    assert any(key.startswith(ip) for key in jailed())
    path.write_text(''.join(line for line in path.read_text().splitlines(keepends=True)
                            if not line.split() or line.split()[0] != ip))
    guard('apply')
    assert all(not key.startswith(ip) for key in jailed())
    for _ in range(3):
        run('ip', 'netns', 'exec', 'guard-client', 'ssh', '-b', ip, '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'ConnectTimeout=3', 'missing-example-account@198.51.100.1', 'true', check=False)
    wait_for(lambda: count() == previous + 1, seconds=90)
    run('/usr/lib/frp-ssh-guard/run', 'log')
    assert count() == previous + 1
    run('/usr/lib/frp-ssh-guard/run', 'strike')
    assert any(key.startswith(ip) for key in vm.jail('hardban4'))
    print('PASS: editable-list deletion permits a new auth offense and strike, counted once', flush=True)


def main():
    assert os.environ.get('FRP_GUARD_DISPOSABLE') == '1' and os.geteuid() == 0
    home = Path('/home/guardmigration/.frp-ssh-guard')
    settings = home / 'settings.conf'
    database = Path('/var/lib/frp-ssh-guard/observations/events.sqlite3')
    def configure(**values):
        content = settings.read_text()
        for key, value in values.items():
            content = re.sub(r'^' + key + r'=.*$', key + '=' + value, content, flags=re.M)
        settings.write_text(content)
        guard('check')
        guard('reload')
    def query(sql, args=()):
        with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
            return db.execute(sql, args).fetchall()
    def attempts(ip, count):
        for _ in range(count):
            run('ip', 'netns', 'exec', 'guard-client', 'ssh', '-b', ip, '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'ConnectTimeout=2', 'missing-example-account@198.51.100.1', 'true', check=False)
    ip = '198.51.100.10'
    run('ip', '-n', 'guard-client', 'addr', 'replace', ip + '/24', 'dev', 'guard-peer')
    # A reused VM journal may have caused the old package to ban these test
    # sources before upgrade. Release only these synthetic fixtures explicitly.
    guard('release', ip)
    initial_slow = query("SELECT count(*) FROM events WHERE kind='slow-threshold' AND ip=?", (ip,))[0][0]
    initial_bans = query("SELECT count(*) FROM events WHERE kind='ban' AND ip=?", (ip,))[0][0]
    configure(SSH_AUTH_FAILURES='100', SSH_INVALID_USER_FAILURES='100', SSH_SLOW_FAILURES='3', SSH_SLOW_MODE='observe')
    attempts(ip, 3)
    wait_for(lambda: query("SELECT count(*) FROM events WHERE kind='slow-threshold' AND ip=?", (ip,))[0][0] == initial_slow + 1, seconds=90)
    assert all(not key.startswith(ip) for key in vm.jail())
    assert query("SELECT count(*) FROM events WHERE kind='ban' AND ip=?", (ip,))[0][0] == initial_bans
    newest = query("SELECT id FROM events WHERE kind='slow-threshold' AND ip=? ORDER BY stamp DESC LIMIT 1", (ip,))[0][0]
    wait_for(lambda: 'id=' + newest in (home / 'alerts.log').read_text(), seconds=30)
    print('PASS: actual sshd failures trigger observation without a ban', flush=True)
    configure(SSH_SLOW_MODE='enforce')
    attempts(ip, 1)
    wait_for(lambda: any(key.startswith(ip) for key in vm.jail()), seconds=90)
    before = next(value for key, value in vm.jail().items() if key.startswith(ip))
    run('/usr/lib/frp-ssh-guard/run', 'log')
    run('/usr/lib/frp-ssh-guard/run', 'log')
    run('systemctl', 'restart', 'frp-ssh-guard-auth')
    time.sleep(3)
    after = next(value for key, value in vm.jail().items() if key.startswith(ip))
    assert after <= before
    assert query("SELECT count(*) FROM events WHERE kind='ban' AND ip=?", (ip,))[0][0] == initial_bans + 1
    attempts(ip, 1)
    run('/usr/lib/frp-ssh-guard/run', 'log')
    assert query('SELECT coalesce(sum(packets),0) FROM samples')[0][0] > 0
    report = guard('report', '1h')
    assert 'Sampled dropped packets:' in report
    assert 'Live native SSH ban rules (IPv4/IPv6): present' in guard('doctor')
    print('PASS: explicit enforcement, direct/sample dedup, restart expiry and actual drop metrics', flush=True)
    other = '198.51.100.11'
    run('ip', '-n', 'guard-client', 'addr', 'replace', other + '/24', 'dev', 'guard-peer')
    guard('release', other)
    configure(SSH_SLOW_MODE='off', SSH_AUTH_FAILURES='5', SSH_INVALID_USER_FAILURES='3', SUBNET_REPORT_MIN_SOURCES='2')
    attempts(other, 3)
    wait_for(lambda: any(key.startswith(other) for key in vm.jail()), seconds=90)
    wait_for(lambda: query("SELECT count(*) FROM events WHERE kind='subnet-cluster'")[0][0] >= 1)
    assert not any('/24' in key or '/64' in key for key in vm.jail())
    print('PASS: fast native SSH protection and subnet report without a subnet ban', flush=True)
    log = home / 'alerts.log'
    assert log.stat().st_uid == int(vm.output('id', '-u', 'guardmigration'))
    assert log.stat().st_mode & 0o777 == 0o600
    original = log.read_text()
    assert original.splitlines() == sorted(set(original.splitlines()), reverse=True)
    assert 'missing-example-account' not in original and 'for root' not in original
    configure(ALERT_LOG_MAX_SIZE='1KiB')
    assert log.stat().st_size <= 1024
    assert not list(home.glob('alerts.log.*'))
    assert guard('report', '1s').find('slow-threshold: 0') >= 0
    print('PASS: private owner log, newest-first complete records, reload cap and report window', flush=True)
    check_reban()


if __name__ == '__main__':
    if sys.argv[1:] == ['reban']:
        check_reban()
    else:
        main()
