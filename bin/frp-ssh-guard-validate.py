#!/usr/bin/env python3
"""Validate policy values before any firewall or service mutation."""
import re
import pwd
import sys


def validate(values):
    def fail(key, expected):
        raise ValueError(f"Invalid {key}={values.get(key)!r}: {expected}. Edit settings.conf and run check.")

    for key in ('PER_IP_RATE', 'PER_IP_BURST', 'GLOBAL_RATE', 'GLOBAL_BURST', 'MAX_LEARNED',
                'SSH_AUTH_FAILURES', 'SSH_INVALID_USER_FAILURES', 'SSH_SLOW_FAILURES', 'SUBNET_REPORT_MIN_SOURCES',
                'SSH_SLOW_TOTAL_CONNECTIONS', 'SSH_SLOW_PORT_CONNECTIONS'):
        value = values[key]
        if not re.fullmatch(r'[1-9][0-9]{0,6}', value) or int(value) > 1000000:
            fail(key, 'expected an integer from 1 to 1000000')
    for key in ('PORT_MIN', 'PORT_MAX'):
        if not re.fullmatch(r'[1-9][0-9]{0,4}', values[key]) or int(values[key]) > 65535:
            fail(key, 'expected a TCP port from 1 to 65535')
    if int(values['PORT_MIN']) > int(values['PORT_MAX']):
        fail('PORT_MIN', 'must not exceed PORT_MAX')
    for key in ('BAN_TIMEOUT', 'LEARN_TIMEOUT', 'STRIKE_WINDOW', 'STRIKE_MAX', 'SSH_AUTH_WINDOW', 'SSH_SLOW_WINDOW', 'SUBNET_REPORT_WINDOW'):
        if not re.fullmatch(r'[1-9][0-9]{0,8}[smhdw]', values[key]):
            fail(key, 'expected a positive duration, e.g. 30m, 6h, 7d, or 4w')
    if values.get('SSH_SLOW_MODE', '') not in ('', 'off', 'observe', 'enforce'):
        fail('SSH_SLOW_MODE', 'this setting is obsolete; delete it and set SSH_SLOW_PROTECTION=on or off')
    size = re.fullmatch(r'([1-9][0-9]*)(KiB|MiB)', values['LOG_MAX_SIZE'])
    if not size or not 1024 <= int(size[1]) * (1024 if size[2] == 'KiB' else 1048576) <= 104857600:
        fail('LOG_MAX_SIZE', 'expected 1KiB to 100MiB')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', values['GUARD_TABLE']):
        fail('GUARD_TABLE', 'expected a simple nftables identifier')
    for key in ('PROTECT_SERVER_SSH', 'JAIL_PER_PORT', 'SSH_SLOW_PROTECTION', 'LEARN_ADMINS'):
        if values[key] not in ('on', 'off'):
            fail(key, 'expected on or off')
    try:
        pwd.getpwnam(values['EDIT_USER'])
    except KeyError:
        fail('EDIT_USER', 'expected an existing local account')
    previous = 1
    for entry in values['STRIKE_LADDER'].split():
        match = re.fullmatch(r'([1-9][0-9]*):([1-9][0-9]{0,8}[smhdw])', entry)
        if not match or int(match[1]) <= previous:
            fail('STRIKE_LADDER', 'use increasing strike counts above 1, e.g. 2:1d 3:3d')
        previous = int(match[1])
    for entry in values['EXCLUDE_PORTS'].replace(',', ' ').split():
        if not re.fullmatch(r'[1-9][0-9]{0,4}(-[1-9][0-9]{0,4})?', entry):
            fail('EXCLUDE_PORTS', 'use comma-separated ports or ranges')
        bounds = [int(p) for p in entry.split('-')]
        if max(bounds) > 65535 or bounds[0] > bounds[-1]:
            fail('EXCLUDE_PORTS', 'ports must be 1–65535 and ranges ascending')


if __name__ == '__main__':
    try:
        validate(dict(arg.split('=', 1) for arg in sys.argv[1:]))
    except ValueError as error:
        sys.exit(str(error))
