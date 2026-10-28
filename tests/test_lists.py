"""Unified lists retain scope, origin and expiry across edits and restarts."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('lists', ROOT / 'bin/frp-ssh-guard-lists.py')
lists = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lists)
data = lists.data


class ListTests(unittest.TestCase):
    def test_tiers_resolve_once_with_custom_policy_and_forever_is_explicit(self):
        rows = data.records('[all]\n198.51.100.1 forever\n[22]\n198.51.100.2 tier=1\n'
                            '198.51.100.3 tier=2\n198.51.100.4 tier=5\n')
        resolved = data.resolve_tiers(rows, '7h', '2:2d 3:4d 4:8d 5:40d', '28d', now=1000)
        self.assertEqual([r.expiry for r in resolved], [0, 26200, 173800, 2420200])
        text = data.render_list('', resolved, 'block')
        self.assertIn('198.51.100.1 forever', text)
        self.assertIn('tier=2 until=', text)
        later = data.resolve_tiers(data.records(text), '1h', '2:1d 3:3d 4:7d 5:28d', '28d', now=2000)
        self.assertEqual(later, resolved)
        for invalid in ('198.51.100.1 forever tier=1', '198.51.100.1 tier=0',
                        '198.51.100.1 tier=6', '198.51.100.1 forever until=2030-01-01T00:00:00Z'):
            with self.assertRaises(ValueError):
                data.records(invalid)
        with self.assertRaises(ValueError):
            data.resolve_tiers(data.records('198.51.100.1 tier=2'), '6h', '', '28d')

    def test_sections_legacy_lines_comments_ipv6_and_expiries(self):
        text = '# custom comment\n[all]\n198.51.100.1\n[22]\n2001:db8::1 source=learned until=2030-01-01T00:00:00Z\n'
        rows = data.records(text, 'allow')
        self.assertEqual(rows[0], data.Row('198.51.100.1'))
        self.assertEqual(rows[1].scope, '22')
        self.assertEqual(rows[1].expiry, 1893456000)
        rendered = data.render_list(text, rows + [data.Row('203.0.113.1', '22001')], 'allow')
        self.assertIn('# custom comment', rendered)
        self.assertIn('[22001]\n203.0.113.1', rendered)
        self.assertEqual(data.render_list(rendered, data.records(rendered, 'allow'), 'allow'), rendered)
        self.assertEqual(data.entries('[22]\n198.51.100.1 all\n'), [('198.51.100.1', '*', 0)])

    def test_shipped_examples_match_generated_headers_and_old_header_is_refreshed(self):
        for kind, name in (('block', 'blocklist'), ('allow', 'whitelist')):
            with self.subTest(kind=kind):
                self.assertEqual((ROOT / 'etc' / (name + '.conf.example')).read_text(), data.render_list('', [], kind))
                body = '\n[all]\n198.51.100.1  # my note\n[22001]\n203.0.113.1\n'
                old = '\n'.join(data.LEGACY_HEADERS[kind]) + '\n' + body
                refreshed = data.render_list(old, data.records(old, kind), kind)
                self.assertTrue(refreshed.startswith('\n'.join(data.HEADERS[kind]) + '\n\n[all]\n'), refreshed)
                self.assertEqual(data.records(refreshed, kind), data.records(old, kind))
                self.assertIn('# my note', refreshed)
                for line in set(data.LEGACY_HEADERS[kind]) - set(data.HEADERS[kind]):
                    self.assertNotIn(line, refreshed.splitlines())
                # A header the user changed is never replaced.
                edited = old.replace('# Delete an entry', '# My own wording. Delete an entry')
                kept = data.render_list(edited, data.records(edited, kind), kind)
                self.assertTrue(kept.startswith(edited.split('\n\n[all]')[0] + '\n\n[all]\n'), kept)
        self.assertIn('blocked FOREVER', '\n'.join(data.HEADERS['block']))
        self.assertNotIn('tier=', '\n'.join(data.HEADERS['allow']))

    def test_default_ban_durations_and_every_shipped_header_refresh(self):
        values = data.settings((ROOT / 'etc/settings.conf.example').read_text())
        rows = data.records(''.join(f'198.51.100.{tier} tier={tier}\n' for tier in range(1, 6)))
        resolved = data.resolve_tiers(rows, values['BAN_TIMEOUT'], values['STRIKE_LADDER'], values['STRIKE_MAX'], now=0)
        self.assertEqual([row.expiry for row in resolved],
                         [12 * 3600, 3 * 86400, 7 * 86400, 30 * 86400, 90 * 86400])
        for kind in ('block', 'allow'):
            for previous in data.PREVIOUS_HEADERS[kind]:
                with self.subTest(kind=kind, lines=len(previous)):
                    self.assertNotEqual(previous, data.HEADERS[kind])
                    old = '\n'.join(previous) + '\n\n[all]\n198.51.100.1\n'
                    self.assertTrue(data.render_list(old, data.records(old, kind), kind)
                                    .startswith('\n'.join(data.HEADERS[kind]) + '\n'))

    def test_each_successful_login_renews_the_learned_whitelist_period(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('etc', 'lists', 'home'):
                (root / name).mkdir()
            cfg = dict(CONFIG_BASE=str(root / 'etc'), MANUAL_DIR=str(root / 'home'), GUARD_TABLE='test_guard',
                       LEARN_TIMEOUT='90d', STRIKE_MAX='90d', MAX_LEARNED='500', JAIL_PER_PORT='off')
            def learn(expiry):
                lists.sync(cfg, addition=('allow', data.Row('198.51.100.30', '*', expiry, 'learned')))
                return [r.expiry for r in data.records((root / 'home/whitelist.conf').read_text(), 'allow')]
            with mock.patch.dict(os.environ, {'GUARD_LIST_DIR': str(root / 'lists')}), \
                 mock.patch.object(lists.time, 'time', return_value=1000), \
                 mock.patch.object(lists, 'snapshot', return_value=[]):
                self.assertEqual(learn(1000 + 90 * 86400), [1000 + 90 * 86400])
                self.assertEqual(learn(1000 + 120 * 86400), [1000 + 120 * 86400])  # a later login renews
                self.assertEqual(learn(1000 + 100 * 86400), [1000 + 120 * 86400])  # an older replay never shortens

    def test_one_section_per_port_with_sorted_automatic_bans(self):
        when = lambda day: f'2030-01-0{day}T00:00:00Z'
        text = ('[all]\n\n[22]\n'
                f'203.0.113.40 source=strike until={when(3)}\n198.51.100.20 source=runtime until={when(1)}\n'
                f'198.51.100.9 source=runtime until={when(1)}\n198.51.100.9 source=strike until={when(4)}\n\n'
                f'[22001]\n198.51.100.77 source=runtime until={when(1)}\n\n'
                f'[22]\n198.51.100.10 source=runtime until={when(1)}\n# my note\n203.0.113.5 forever\n\n'
                f'[22001]\n203.0.113.9 source=runtime until={when(2)}\n\n'
                f'[22]\n198.51.100.100 source=runtime until={when(2)}\n')
        out = data.render_list(text, data.records(text), 'block')
        body = out[out.index('\n[all]\n') + 1:]
        self.assertEqual(body.count('[22001]'), 1)
        self.assertEqual(body.count('[22]'), 2)  # the user's own note keeps its section
        automatic = [line.split()[0] for line in body.split('[22001]')[0].splitlines() if 'source=' in line]
        self.assertEqual(automatic, ['198.51.100.9', '198.51.100.9', '198.51.100.10', '198.51.100.20',
                                     '198.51.100.100', '203.0.113.40'])  # numeric order, pairs together
        self.assertIn('198.51.100.9 source=runtime until=2030-01-01T00:00:00Z\n'
                      '198.51.100.9 source=strike until=2030-01-04T00:00:00Z', body)
        self.assertIn('# my note\n203.0.113.5 forever', body)
        self.assertEqual(sorted(data.records(out)), sorted(data.records(text)))
        self.assertEqual(data.render_list(out, data.records(out), 'block'), out)

    def test_new_entries_join_the_existing_section_for_their_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'blocklist.conf'
            path.write_text(data.render_list('', [data.Row('198.51.100.1', '22001'), data.Row('198.51.100.2', '22003')], 'block'))
            data.edit_list(path, 'block', 'add', '198.51.100.3', '22001', 0)
            text = path.read_text()
            self.assertEqual(text.splitlines().count('[22001]'), 1)  # header comments mention it too
            self.assertIn('\n[22001]\n198.51.100.1 forever\n198.51.100.3 forever\n', text)

    def test_list_errors_name_the_problem(self):
        for text, message in (('203.0.113.10 7d', 'no time means forever'),
                              ('203.0.113.10 for=7d', 'not a supported option'),
                              ('203.0.113.10 until=tomorrow', 'until=2030-01-31T00:00:00Z'),
                              ('[ports]', 'Use all, or comma-separated')):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'line 1: .*' + message):
                data.records(text)
        with self.assertRaisesRegex(ValueError, 'Invalid whitelist entry on line 2: tier= is only used in the blocklist'):
            data.records('198.51.100.1\n198.51.100.2 tier=2\n', 'allow')

    def test_trusted_sources_cover_every_scope_without_overlaps(self):
        text = ('[22001]\n198.51.100.0/24\n198.51.100.7\n198.51.100.9 source=learned until=2030-01-01T00:00:00Z\n'
                '[22003]\n198.51.100.7\n203.0.113.5 source=learned until=2030-01-01T00:00:00Z\n'
                '[all]\n203.0.113.5 source=learned until=2031-01-01T00:00:00Z\n'
                '203.0.113.6 source=learned until=2001-01-01T00:00:00Z\n2001:db8::/64\n2001:db8::1\n')
        self.assertEqual(data.trusted_sources(text, now=1000000000),
                         [(4, '198.51.100.0/24', 0), (6, '2001:db8::/64', 0), (4, '203.0.113.5', 1924992000)])
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {'GUARD_LIST_DIR': tmp}):
            Path(tmp, 'whitelist.conf').write_text(text)
            self.assertTrue(lists.listed('198.51.100.200'))
            self.assertTrue(lists.listed('2001:db8::abcd'))
            self.assertFalse(lists.listed('203.0.113.6'))  # expired learned entry
            self.assertFalse(lists.listed('192.0.2.1'))

    def test_covered_entries_are_kept_out_of_nftables_and_partial_overlaps_refused(self):
        rows = data.records('198.51.100.0/24\n198.51.100.7\n198.51.100.7 until=2030-01-01T00:00:00Z\n'
                            '[22001-22003]\n203.0.113.0/24\n[22002]\n203.0.113.5\n'
                            '203.0.113.6 source=runtime until=2030-01-01T00:00:00Z\n'
                            '[22001]\n203.0.113.6 source=runtime until=2031-01-01T00:00:00Z\n')
        skips = data.redundant_elements(rows, 'block')
        self.assertEqual(skips, {1: {'*'}, 2: {'*'}, 4: {'22002'}})  # automatic and manual sets differ
        for text in ('198.51.100.0/24 until=2030-01-01T00:00:00Z\n198.51.100.7\n',   # wider but shorter
                     '[22001-22002]\n203.0.113.0/24\n[22002-22003]\n203.0.113.5\n'):  # ports only partly covered
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'lines 1 and 2 overlap'):
                data.redundant_elements(data.records(text, 'block'), 'block', [1, 2])
        # Learned addresses in [all] use an address-only set: duplicates are fine there.
        learned = data.records('198.51.100.9 source=learned until=2030-01-01T00:00:00Z\n'
                               '[22]\n198.51.100.9 source=learned until=2031-01-01T00:00:00Z\n'
                               '[22,22001]\n198.51.100.9 source=learned until=2030-01-01T00:00:00Z\n', 'allow')
        self.assertEqual(data.redundant_elements(learned, 'allow'), {2: {'22'}})

    def test_administrators_are_learned_without_configured_usernames(self):
        import types
        config = dict(LEARN_ADMINS='on', LOGIN_USERS='', CONFIG_BASE='/nonexistent')
        accounts = {'opsadmin': 1001, 'deploy': 1002, 'owner': 1003}
        groups = {'sudo': 27, 'wheel': 10}
        memberships = {'opsadmin': [1001, 27], 'deploy': [1002], 'owner': [1003]}
        def getpwnam(name):
            if name not in accounts:
                raise KeyError(name)
            return types.SimpleNamespace(pw_gid=accounts[name])
        def getgrnam(name):
            if name not in groups:
                raise KeyError(name)
            return types.SimpleNamespace(gr_gid=groups[name])
        with mock.patch.object(lists.pwd, 'getpwnam', side_effect=getpwnam), \
             mock.patch.object(lists.grp, 'getgrnam', side_effect=getgrnam), \
             mock.patch.object(lists.os, 'getgrouplist', side_effect=lambda user, gid: memberships[user]), \
             mock.patch.object(lists.data, 'location', return_value={'user': 'owner'}):
            self.assertTrue(lists.learning(config))
            self.assertTrue(lists.learnable('root', config))
            self.assertTrue(lists.learnable('opsadmin', config))   # sudo member
            self.assertTrue(lists.learnable('owner', config))      # owns the settings folder
            self.assertFalse(lists.learnable('deploy', config))
            self.assertFalse(lists.learnable('nobody-here', config))
            self.assertTrue(lists.learnable('deploy', {**config, 'LOGIN_USERS': 'deploy|ci'}))
            off = {**config, 'LEARN_ADMINS': 'off'}
            self.assertFalse(lists.learning(off))
            self.assertFalse(lists.learnable('root', off))
            self.assertTrue(lists.learnable('deploy', {**off, 'LOGIN_USERS': 'deploy'}))

    def test_invalid_sections_metadata_and_automatic_permanent_entries_fail(self):
        for text in ('[0]\n', '[65536]\n', '[22] junk\n', '[22-21]\n',
                     '198.51.100.1 source=runtime\n', '198.51.100.1 source=unknown\n',
                     '198.51.100.1 until=2030-01-01T00:00:00Z until=2030-01-01T00:00:00Z'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                data.records(text)

    def test_matching_all_and_port_scopes_and_expiry(self):
        self.assertTrue(lists.matches(data.Row('198.51.100.0/24'), '198.51.100.9', 22, 100))
        self.assertFalse(lists.matches(data.Row('198.51.100.9', '22001'), '198.51.100.9', 22, 100))
        self.assertTrue(lists.matches(data.Row('2001:db8::9', '22,22001-22003', 101), '2001:db8::9', 22, 100))
        self.assertFalse(lists.matches(data.Row('2001:db8::9', '*', 100), '2001:db8::9', 22, 100))

    def test_deleted_auto_entry_is_not_resurrected_but_new_attack_can_reban(self):
        row = data.Row('198.51.100.9', '22', 1000, 'runtime')
        deleted = {}
        rows, removals = lists.reconcile('[22]\n', {lists.key(row): 1000}, [('ban4', row)], deleted, 100, 'block')
        self.assertEqual(rows, [])
        self.assertEqual(removals, [('ban4', row)])
        rows, _ = lists.reconcile('[22]\n', {}, [('ban4', row)], deleted, 101, 'block')
        self.assertEqual(rows, [])
        newer = row._replace(expiry=1200)
        rows, _ = lists.reconcile('[22]\n', {}, [('ban4', newer)], deleted, 102, 'block')
        self.assertEqual(rows, [newer])

    def test_kernel_seconds_rounding_does_not_extend_saved_deadline(self):
        row = data.Row('198.51.100.9', '*', 1000, 'runtime')
        text = data.render_list('', [row], 'block')
        rows, _ = lists.reconcile(text, {}, [('ban4', row._replace(expiry=1001))], {}, 100, 'block')
        self.assertEqual(rows, [row])
        rows, _ = lists.reconcile(text, {}, [], {}, 1001, 'block')
        self.assertEqual(rows, [])

    def test_sync_migrates_once_preserves_ttl_and_comments_without_timer_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'etc').mkdir()
            (root / 'lists').mkdir()
            (root / 'home').mkdir()
            (root / 'home/whitelist.conf').write_text('# keep me\n198.51.100.1\n')
            (root / 'home/blocklist.conf').write_text('# my blocks\n[22]\n203.0.113.1\n')
            (root / 'lists/learned.conf').write_text('198.51.100.2\n')
            cfg = dict(CONFIG_BASE=str(root / 'etc'), MANUAL_DIR=str(root / 'home'), GUARD_TABLE='test_guard',
                       LEARN_TIMEOUT='90d', STRIKE_MAX='28d', MAX_LEARNED='500')
            row = data.Row('198.51.100.2', '*', 1100, 'learned')
            with mock.patch.dict(os.environ, {'GUARD_LIST_DIR': str(root / 'lists')}), \
                 mock.patch.object(lists.time, 'time', return_value=1000), \
                 mock.patch.object(lists, 'snapshot', return_value=[('learned4', row)]), \
                 mock.patch.object(lists.subprocess, 'run') as run:
                lists.sync(cfg)
                first = (root / 'home/whitelist.conf').read_text()
                self.assertIn('# keep me', first)
                self.assertIn(row, data.records(first, 'allow'))
                lists.sync(cfg)
                self.assertEqual((root / 'home/whitelist.conf').read_text(), first)
                run.assert_not_called()
                lists.sync(cfg, addition=('allow', row._replace(expiry=1101)))
                self.assertIn(row._replace(expiry=1101), data.records((root / 'home/whitelist.conf').read_text(), 'allow'))
            with mock.patch.dict(os.environ, {'GUARD_LIST_DIR': str(root / 'lists')}), \
                 mock.patch.object(lists.time, 'time', return_value=1200), \
                 mock.patch.object(lists, 'snapshot', return_value=[]):
                lists.sync(cfg)
            self.assertNotIn('198.51.100.2', (root / 'home/whitelist.conf').read_text())

    def test_mode_switches_keep_deadlines_and_explicit_manual_scopes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('etc', 'lists', 'home'):
                (root / name).mkdir()
            cfg = dict(CONFIG_BASE=str(root / 'etc'), MANUAL_DIR=str(root / 'home'),
                       GUARD_TABLE='test_guard', LEARN_TIMEOUT='90d', STRIKE_MAX='28d',
                       MAX_LEARNED='500', JAIL_PER_PORT='on')
            original = [data.Row('198.51.100.8', '22', 1400, 'runtime'),
                        data.Row('198.51.100.8', '22001', 1600, 'runtime'),
                        data.Row('198.51.100.8', '22', 1800, 'strike'),
                        data.Row('2001:db8::8', '22001,22003', 1500, 'runtime'),
                        data.Row('203.0.113.8', '*', 1700, 'runtime'),
                        data.Row('203.0.113.9', '22003')]
            path = root / 'home/blocklist.conf'
            path.write_text(data.render_list('# keep this comment\n', original, 'block'))
            with mock.patch.dict(os.environ, {'GUARD_LIST_DIR': str(root / 'lists')}), \
                 mock.patch.object(lists.time, 'time', return_value=1000), \
                 mock.patch.object(lists, 'snapshot', return_value=[]):
                lists.sync(cfg)
                self.assertEqual(set(data.records(path.read_text())), set(original))
                cfg['JAIL_PER_PORT'] = 'off'
                lists.sync(cfg)
                expected = set(original)
                self.assertEqual(set(data.records(path.read_text())), expected)
                self.assertIn('# keep this comment', path.read_text())
                cfg['JAIL_PER_PORT'] = 'on'
                lists.sync(cfg)
                self.assertEqual(set(data.records(path.read_text())), expected)
                # Offline-home reload and restoration retain every original scope.
                (root / 'home').rename(root / 'offline')
                lists.sync(cfg)
                self.assertEqual(set(data.records((root / 'lists/blocklist.conf').read_text())),
                                 {r for r in expected if r.source != 'manual'})
                (root / 'offline').rename(root / 'home')
                # Explicit removal must still suppress the existing jail generation.
                path.write_text(data.render_list(path.read_text(),
                                [r for r in expected if r.ip != '198.51.100.8'], 'block'))
                with mock.patch.object(lists, 'snapshot', return_value=[('ban4', original[0])]), \
                     mock.patch.object(lists.subprocess, 'run'):
                    lists.sync(cfg)
                self.assertFalse(any(r.ip == '198.51.100.8' for r in data.records(path.read_text())))

    def test_concurrent_editor_and_symlink_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'whitelist.conf'
            path.write_text('new edit\n')
            with self.assertRaises(ValueError):
                data.replace_list(path, 'old edit\n', 'replacement\n')
            link = Path(tmp) / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                data.replace_list(link, 'new edit\n', 'replacement\n')
            self.assertEqual(path.read_text(), 'new edit\n')

    def test_nft_snapshot_requires_expiry_and_preserves_port_keys(self):
        doc = {'nftables': [{'set': {'name': 'ban6', 'elem': [
            {'elem': {'val': {'concat': ['2001:db8::1', 22]}, 'expires': 120}},
            {'elem': {'val': '2001:db8::2'}}]}}]}
        self.assertEqual(lists.kernel_rows(doc, 1000), [('ban6', data.Row('2001:db8::1', '22', 1120, 'runtime'))])


if __name__ == '__main__':
    unittest.main()
