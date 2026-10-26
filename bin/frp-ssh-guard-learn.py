#!/usr/bin/env python3
"""Learn expiring whitelist entries from trusted successful local SSH logins."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

LIB = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, LIB / ('frp-ssh-guard-' + name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


lists, auth = module('lists'), module('auth')
SUCCESS = re.compile(r'^Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) for (\S+) from ')


def accepted(record, users):
    event = auth.parse_event(record)
    if not users or not event or event[0] != 'accepted':
        return None
    match = SUCCESS.match(record['MESSAGE'])
    if not match:
        return None
    # Preserve the documented POSIX extended-regex interpretation of LOGIN_USERS.
    matched = subprocess.run(['grep', '-Ex', '--', users], input=match[1] + '\n',
                             text=True, stdout=subprocess.DEVNULL).returncode == 0
    return (event[1], event[3]) if matched else None


def learn(record):
    event = auth.parse_event(record)
    if not event or event[0] != 'accepted':
        return False  # failed/noisy journal records need no lock or policy subprocess
    lock_path = os.environ.get('GUARD_LOCK_FILE', '/run/frp-ssh-guard.lock')
    with open(lock_path, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        config = lists.policy()
        success = accepted(record, config['LOGIN_USERS'])
        if not success:
            return False
        ip, stamp = success
        expiry = int(stamp) + lists.data.duration(config['LEARN_TIMEOUT'])
        if expiry <= time.time() or stamp > time.time() + 5:
            return False
        path = Path(config['MANUAL_DIR']) / 'whitelist.conf'
        if not path.exists():
            path = lists.state_directory() / 'whitelist.conf'
        if any(row.ip == ip and row.scope == '*' and row.source == 'learned' and row.expiry >= expiry
               for row in lists.data.records(lists.read(path), 'allow')):
            return False  # replaying older successes must not reapply the lists
        lists.sync(config, addition=('allow', lists.data.Row(ip, '*', expiry, 'learned')))
    command = os.environ.get('GUARD_COMMAND', str(Path(os.environ.get('GUARD_DIR', '/opt/frp-ssh-guard')) / 'bin/frp-ssh-guard'))
    subprocess.run([command, 'apply'], check=True, stdout=subprocess.DEVNULL)
    if shutil.which('fail2ban-client'):
        subprocess.run(['fail2ban-client', 'set', 'sshd', 'addignoreip', ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('Trusted local SSH login refreshed the unified whitelist.', flush=True)
    return True


def main():
    events = module('events')
    current = events.policy()
    if current['OBSERVABILITY_VERSION'] == '1':
        if not current['LOGIN_USERS']:
            return 0
        return events.follow('learn')
    config = lists.policy()
    if not config['LOGIN_USERS']:
        print('Auto-learning disabled: set LOGIN_USERS, then check and reload.')
        return 0
    path = lists.state_directory() / 'learn-cursor.json'
    state = json.loads(lists.read(path) or '{}')
    command = ['journalctl', '--no-pager', '--output=json', '--follow', '_UID=0',
               'SYSLOG_IDENTIFIER=sshd', 'SYSLOG_IDENTIFIER=sshd-session', 'SYSLOG_IDENTIFIER=sshd-auth']
    for resume in (True, False):
        position = ['--after-cursor=' + state['cursor']] if resume and state.get('cursor') else ['-n', '1000']
        process = subprocess.Popen(command + position, stdout=subprocess.PIPE, text=True)
        try:
            for line in process.stdout:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                learn(record)
                if record.get('__CURSOR'):
                    state = {'cursor': record['__CURSOR']}
                    lists.data.atomic_write(path, json.dumps(state) + '\n')
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate()
            process.wait()
        if process.returncode == 0 or not state.get('cursor'):
            break
    return 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError):
        sys.exit('Could not update the learned whitelist; inspect list access/format and retry reload.')
