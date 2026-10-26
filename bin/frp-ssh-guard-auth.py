#!/usr/bin/env python3
"""Observe trusted local sshd outcomes; never read or retain attempted passwords."""
import fcntl
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

LIB = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('guard_input', LIB / 'frp-ssh-guard-input.py')
data = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(data)
LIST_SPEC = importlib.util.spec_from_file_location('guard_lists', LIB / 'frp-ssh-guard-lists.py')
lists = importlib.util.module_from_spec(LIST_SPEC)
LIST_SPEC.loader.exec_module(lists)
KEYS = ('PROTECT_SERVER_SSH', 'JAIL_PER_PORT', 'GUARD_TABLE', 'BAN_TIMEOUT',
        'SSH_AUTH_FAILURES', 'SSH_INVALID_USER_FAILURES', 'SSH_AUTH_WINDOW')
OUTCOME = re.compile(r'^(Failed|Accepted) (?:password|publickey|keyboard-interactive(?:/pam)?) '
                     r'for (invalid user )?.* from (\S+) port ([0-9]+)(?: ssh[12])?(?:[: ].*)?$')
INVALID = re.compile(r'^Invalid user .* from (\S+) port ([0-9]+)(?: \[preauth\])?$')


def load_policy():
    result = subprocess.run(['bash', '-ec',
        '. "$1"; load_guard_config runtime; shift; for key; do printf "%s\\0" "${!key}"; done',
        'guard-auth', str(LIB / 'frp-ssh-guard-config.sh'), *KEYS],
        check=True, capture_output=True, text=True)
    return dict(zip(KEYS, result.stdout.rstrip('\0').split('\0')))


def parse_event(record):
    if record.get('_UID') != '0' or record.get('SYSLOG_IDENTIFIER') not in ('sshd', 'sshd-session', 'sshd-auth'):
        return None
    message = record.get('MESSAGE')
    if not isinstance(message, str) or '\n' in message:
        return None
    match = OUTCOME.fullmatch(message)
    if match:
        outcome, invalid, raw_ip, port = match.groups()
        kind = 'accepted' if outcome == 'Accepted' else ('invalid' if invalid else 'failed')
    else:
        match = INVALID.fullmatch(message)
        if not match:
            return None
        raw_ip, port = match.groups()
        kind = 'invalid'
    try:
        ip = ipaddress.ip_address(raw_ip)
        if ip.is_loopback or ip.is_unspecified or '%' in raw_ip or not 1 <= int(port) <= 65535:
            return None
        stamp = int(record['__REALTIME_TIMESTAMP']) / 1000000
    except (ValueError, KeyError, TypeError):
        return None
    # The username is deliberately discarded; sshd's invalid-user result is enough.
    return kind, str(ip), record.get('_PID', '') + ':' + port, stamp


class Tracker:
    def __init__(self, policy, state=None):
        self.window = data.duration(policy['SSH_AUTH_WINDOW'])
        self.failures = int(policy['SSH_AUTH_FAILURES'])
        self.invalid = int(policy['SSH_INVALID_USER_FAILURES'])
        self.state = state or {'attempts': {}, 'seen': [], 'cursor': ''}
        self.seen = set(self.state['seen'])

    def process(self, record, now=None):
        now = time.time() if now is None else now
        cursor = record.get('__CURSOR', '')
        if not cursor or cursor in self.seen:
            return None
        self.seen.add(cursor)
        self.state['seen'].append(cursor)
        if len(self.state['seen']) > 4096:
            self.seen.discard(self.state['seen'].pop(0))
        self.state['cursor'] = cursor
        event = parse_event(record)
        if not event:
            return None
        kind, ip, connection, stamp = event
        if stamp < now - self.window or stamp > now + 5:
            return None
        attempts = self.state['attempts']
        if kind == 'accepted':
            attempts.pop(ip, None)
            return None
        if len(attempts) >= 10000 and ip not in attempts:
            oldest = min(attempts, key=lambda key: attempts[key][-1][0])
            attempts.pop(oldest)
        previous = [entry for entry in attempts.get(ip, []) if entry[0] >= now - self.window]
        # Invalid-user and failed-password messages can describe the same attempt.
        if kind == 'invalid' and any(e[1] and e[2] == connection for e in previous):
            return None
        previous.append([stamp, kind == 'invalid', connection])
        attempts[ip] = previous
        if len(previous) >= self.failures or sum(e[1] for e in previous) >= self.invalid:
            attempts.pop(ip, None)
            return ip
        return None


def ban(ip):
    lock_path = os.environ.get('GUARD_LOCK_FILE', '/run/frp-ssh-guard.lock')
    with open(lock_path, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        policy = load_policy()
        if policy['PROTECT_SERVER_SSH'] != 'on':
            return False
        if lists.allowed(ip, 22):
            return None
        table = policy['GUARD_TABLE']
        if subprocess.run(['nft', 'list', 'table', 'inet', table], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode:
            return False
        ip = str(ipaddress.ip_address(ip))
        value = ip + (' . 22' if policy['JAIL_PER_PORT'] == 'on' else '')
        name = 'ban6' if ':' in ip else 'ban4'
        result = subprocess.run(['nft', 'add', 'element', 'inet', table, name,
                                 '{ ' + value + ' timeout ' + policy['BAN_TIMEOUT'] + ' }'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            lists.sync()
            return True
        return False


def main():
    policy = load_policy()
    if policy['PROTECT_SERVER_SSH'] != 'on':
        print('Local SSH authentication protection is disabled.')
        return 0
    path = Path(os.environ.get('GUARD_DIR', '/opt/frp-ssh-guard')) / 'auth-state.json'
    try:
        state = json.loads(path.read_text())
        if not isinstance(state['attempts'], dict) or not isinstance(state['seen'], list):
            raise ValueError('Invalid auth state')
    except FileNotFoundError:
        state = None
    tracker = Tracker(policy, state)
    # Journal-owned UID metadata prevents unprivileged syslog messages from counting.
    command = ['journalctl', '--no-pager', '--output=json', '--follow', '_UID=0',
               'SYSLOG_IDENTIFIER=sshd', 'SYSLOG_IDENTIFIER=sshd-session', 'SYSLOG_IDENTIFIER=sshd-auth']
    for resume in (True, False):
        position = ['--after-cursor=' + tracker.state['cursor']] if resume and tracker.state['cursor'] else ['--since=-' + str(tracker.window) + 's']
        process = subprocess.Popen(command + position, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            for line in process.stdout:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                ip = tracker.process(record)
                if ip:
                    result = ban(ip)
                    if result is True:
                        print('SSH authentication threshold reached; guard ban applied.', flush=True)
                    elif result is False:
                        print('SSH authentication threshold reached; guard ban could not be applied.', file=sys.stderr, flush=True)
                data.atomic_write(path, json.dumps(tracker.state) + '\n')
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate()
            process.wait()
        if process.returncode == 0 or not tracker.state['cursor']:
            break
    return 1  # systemd restarts a broken journal stream; persisted cursor avoids replay


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError):
        sys.exit('Could not read accepted SSH protection policy or journal state.')
