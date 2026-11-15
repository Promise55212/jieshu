"""Offline contracts for UDP ownership, shared quotas and fail-closed audits.

Kernel packet-flow acceptance is run separately in isolated Linux namespaces.
"""
import copy
import argparse
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest import mock

if sys.platform == 'win32':
    # Import only: these offline cases never invoke a POSIX manager lock.
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('socks5_udp_core_test', ROOT / 'socks5.py')
core = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(core)


def match(left, right, op='=='):
    return {'match': {'op': op, 'left': left, 'right': right}}


def port(protocol, field, number):
    return match({'payload': {'protocol': protocol, 'field': field}}, number)


def family(name):
    return match({'meta': {'key': 'nfproto'}}, name)


def udp_key(node, incoming=True):
    # Handwritten from actual nft JSON, intentionally without redundant UDP meta.
    return [match({'socket': {'key': 'cgroupv2'}}, 's5u' + node['instance'] + '.slice'),
            match({'ct': {'key': 'direction'}}, 'original' if incoming else 'reply'),
            port('udp', 'dport' if incoming else 'sport', {'range': node['udp_range']})]


class UdpContracts(unittest.TestCase):
    def setUp(self):
        self.node = {'id': 'lab', 'instance': 'a' * 32, 'port': 41004,
                     'udp_range': [55000, 55063], 'udp_ext_range': [32768, 54999],
                     'ip_limit': 1, 'sticky': 120,
                     'username': 'labuser', 'password': 'labpass', 'public_host': 'proxy.example.com',
                     'connections': 64, 'maxconn': 128,
                     'expires': 2000000000,
                     'quota': {'original': 10000, 'saved': 0, 'reset_at': 0},
                     'phase': 'active', 'pending': False, 'pending_ip': False}

    def rule(self, table, chain, kind, expressions, owner=None):
        node = self.node if owner is None else owner
        prefix = {'s5m_ip': 's5m-ip-', 's5m_quota': 's5m-q-', 's5m_udp': 's5m-u-'}[table]
        return {'rule': {'family': 'inet', 'table': table, 'chain': chain,
                         'handle': 100, 'comment': prefix + str(node['port']) + '-' + kind,
                         'expr': expressions}}

    def base(self, table):
        chains = [('inbound', 'input', -10)] if table == 's5m_ip' else [
            ('inbound', 'input', -20 if table == 's5m_udp' else 0),
            ('outbound', 'output', -20 if table == 's5m_udp' else 0)]
        return [{'table': {'family': 'inet', 'name': table}}] + [
            {'chain': {'family': 'inet', 'table': table, 'name': chain, 'type': 'filter',
                       'hook': hook, 'prio': priority, 'policy': 'accept'}}
            for chain, hook, priority in chains]

    def table_text(self, snapshot, owner=None, level=1):
        node = self.node if owner is None else owner
        return '\n'.join('socket cgroupv2 level ' + str(level) + ' "s5u' + node['instance']
                         + '.slice" comment "' + row['rule']['comment'] + '"'
                         for row in snapshot if 'rule' in row)

    def quota_snapshot(self, udp=True, exhausted=False):
        result = self.base('s5m_quota')
        if not exhausted:
            result += [{'counter': {'name': 's5m_ci_41004', 'bytes': 40}},
                       {'counter': {'name': 's5m_co_41004', 'bytes': 60}},
                       {'quota': {'name': 's5m_q_41004', 'bytes': 10000, 'used': 100, 'inv': True}}]
        for incoming, suffix, chain in ((True, 'in', 'inbound'), (False, 'out', 'outbound')):
            key = [port('tcp', 'dport' if incoming else 'sport', 41004)]
            drop = ([] if exhausted else [{'quota': 's5m_q_41004'}]) + [{'drop': None}]
            result.append(self.rule('s5m_quota', chain, 'drop' + suffix, key + drop))
            if not exhausted:
                result.append(self.rule('s5m_quota', chain, 'count' + suffix,
                                        key + [{'counter': 's5m_ci_41004' if incoming else 's5m_co_41004'}]))
            if udp:
                result.append(self.rule('s5m_quota', chain, 'udpdrop' + suffix,
                                        udp_key(self.node, incoming) + drop))
                if not exhausted:
                    result.append(self.rule('s5m_quota', chain, 'udpcount' + suffix,
                                            udp_key(self.node, incoming)
                                            + [{'counter': 's5m_ci_41004' if incoming else 's5m_co_41004'}]))
        return result

    def ip_snapshot(self, udp=True):
        result = self.base('s5m_ip')
        if udp:
            result.append({'chain': {'family': 'inet', 'table': 's5m_ip', 'name': 'outbound',
                                     'type': 'filter', 'hook': 'output', 'prio': -10, 'policy': 'accept'}})
        result.append({'set': {'name': 's5m_i4_41004', 'type': 'ipv4_addr', 'size': 1,
                               'flags': ['timeout', 'dynamic'], 'timeout': 120}})
        source = {'payload': {'protocol': 'ip', 'field': 'saddr'}}
        member = match(source, '@s5m_i4_41004')
        def dyn(action):
            return {'set': {'op': action, 'set': 's5m_i4_41004',
                            'elem': {'val': source, 'timeout': 120}}}
        result += [self.rule('s5m_ip', 'inbound', 'local',
                             [family('ipv4'), match({'meta': {'key': 'iifname'}}, 'lo'),
                              port('tcp', 'dport', 41004), {'accept': None}]),
                   self.rule('s5m_ip', 'inbound', 'family',
                             [family('ipv6'), port('tcp', 'dport', 41004), {'drop': None}]),
                   self.rule('s5m_ip', 'inbound', 'refresh',
                             [port('tcp', 'dport', 41004), member, dyn('update'), {'accept': None}]),
                   self.rule('s5m_ip', 'inbound', 'claim',
                             [port('tcp', 'dport', 41004), dyn('add'), {'accept': None}]),
                   self.rule('s5m_ip', 'inbound', 'drop',
                             [family('ipv4'), port('tcp', 'dport', 41004), {'drop': None}])]
        if udp:
            result += [self.rule('s5m_ip', 'inbound', 'udprefresh',
                                 udp_key(self.node) + [member, dyn('update'), {'accept': None}]),
                       self.rule('s5m_ip', 'inbound', 'udpclaim',
                                 udp_key(self.node) + [dyn('add'), {'accept': None}]),
                       self.rule('s5m_ip', 'inbound', 'udpdrop', udp_key(self.node) + [{'drop': None}])]
            destination = {'payload': {'protocol': 'ip', 'field': 'daddr'}}
            def outdyn(action):
                return {'set': {'op': action, 'set': 's5m_i4_41004',
                                'elem': {'val': destination, 'timeout': 120}}}
            result += [self.rule('s5m_ip', 'outbound', 'udpoutrefresh', udp_key(self.node, False)
                                 + [match(destination, '@s5m_i4_41004'), outdyn('update'), {'accept': None}]),
                       self.rule('s5m_ip', 'outbound', 'udpoutclaim', udp_key(self.node, False)
                                 + [outdyn('add'), {'accept': None}]),
                       self.rule('s5m_ip', 'outbound', 'udpoutdrop', udp_key(self.node, False) + [{'drop': None}])]
        return result

    def guard_snapshot(self):
        result = self.base('s5m_udp')
        for incoming, prefix, chain in ((True, 'in', 'inbound'), (False, 'out', 'outbound')):
            client = udp_key(self.node, incoming)
            server = copy.deepcopy(client)
            server[1]['match']['right'] = 'reply' if incoming else 'original'
            server[2]['match']['op'] = '!='
            result += [self.rule('s5m_udp', chain, prefix + 'expiry',
                                 [match({'meta': {'key': 'l4proto'}}, 'udp'), client[0],
                                  match({'meta': {'key': 'time'}}, '2033-05-18 03:33:20', '>='), {'drop': None}]),
                       self.rule('s5m_udp', chain, prefix + 'client',
                                 [family('ipv4')] + client + [{'accept': None}]),
                       self.rule('s5m_udp', chain, prefix + 'server',
                                 [family('ipv4')] + server + [{'accept': None}]),
                       self.rule('s5m_udp', chain, prefix + 'drop',
                                 [match({'meta': {'key': 'l4proto'}}, 'udp'), client[0], {'drop': None}])]
        return result

    def test_opt_in_and_legacy_config_are_separate(self):
        legacy = {k: v for k, v in self.node.items() if k != 'udp_range'}
        cfg = core.proxy_config(legacy, {'wan_if': 'eth0'})
        self.assertIn('deny labuser * * * UDPASSOC,BIND', cfg)
        self.assertNotIn('intport', cfg)
        self.assertNotIn('nserver', cfg)
        self.assertTrue(cfg.endswith('socks -4 -p41004 -i0.0.0.0 -Deeth0\n'))
        cfg = core.proxy_config(self.node, {'wan_if': 'eth0'})
        self.assertIn('parent 1000 intport 0.0.0.0 55000-55063', cfg)
        self.assertIn('parent 1000 extport 0.0.0.0 32768-54999', cfg)
        self.assertIn('allow labuser * * * UDPASSOC\nparent 1000 intport ', cfg)
        self.assertIn('allow labuser * * * CONNECT\ndeny *', cfg)
        self.assertIn('nserver 1.1.1.1/tcp', cfg)
        self.assertIn('deny labuser * 0.0.0.0/8', cfg)
        self.assertIn(' * CONNECT,UDPASSOC\n', cfg)
        self.assertIn('-Niproxy.example.com', cfg)
        self.assertIsNone(core.parser().parse_args(['add', '--seconds', '60']).udp_range)

    def test_invalid_range_and_overlapping_account_rejected(self):
        for value in ([True, 55001], [55000, 55256], [1, 5], [55000], '55000-55001'):
            with self.subTest(value=value), self.assertRaises(core.Fail):
                core.udp_range({'udp_range': value})
        with self.assertRaises(core.Fail):
            core.new_udp_range('55063-55080', [self.node])
        with mock.patch.object(core.Path, 'read_text', return_value='32768 60999'):
            with self.assertRaises(core.Fail):core.new_udp_range('62000-62063', [])

    def test_generated_quota_rules_share_one_balance_and_counters(self):
        with mock.patch.object(core, 'delete_block', return_value=[]), mock.patch.object(core, 'execute_batch') as execute:
            core.apply_quota(self.node)
        lines = execute.call_args.args[0]
        self.assertEqual(sum(line.startswith('add quota ') for line in lines), 1)
        self.assertEqual(sum('quota name "s5m_q_41004"' in line for line in lines), 4)
        self.assertEqual(sum('counter name "s5m_ci_41004"' in line for line in lines), 2)
        self.assertEqual(sum('counter name "s5m_co_41004"' in line for line in lines), 2)
        self.assertFalse(any('s5m_udp_q' in line for line in lines))
        self.node['quota']['saved'] = 10000
        with mock.patch.object(core, 'delete_block', return_value=[]), mock.patch.object(core, 'execute_batch') as execute:
            core.apply_quota(self.node)
        lines = execute.call_args.args[0]
        self.assertEqual(len(lines), 4)
        self.assertTrue(all(' drop comment ' in line for line in lines))
        self.assertFalse(any('add quota ' in line or 'counter name ' in line for line in lines))

    def test_udp_activity_uses_same_ip_set_and_timeout(self):
        with mock.patch.object(core, 'delete_block', return_value=[]), \
                mock.patch.object(core, 'ensure_udp_ip_output'), mock.patch.object(core, 'execute_batch') as execute:
            core.apply_ip(self.node)
        lines = execute.call_args.args[0]
        self.assertEqual(sum('add set ' in line for line in lines), 1)
        udp = [line for line in lines if 'udp dport ' in line]
        self.assertEqual(len(udp), 3)
        self.assertIn('update @s5m_i4_41004 { ip saddr timeout 120s }', udp[0])
        self.assertIn('add @s5m_i4_41004 { ip saddr timeout 120s }', udp[1])
        self.assertIn(' drop comment ', udp[2])
        down = [line for line in lines if 'udp sport ' in line]
        self.assertEqual(len(down), 3)
        self.assertTrue(all('ct direction reply' in line and 'outbound ' in line for line in down))
        self.assertIn('ip daddr @s5m_i4_41004 update @s5m_i4_41004 { ip daddr timeout 120s }', down[0])
        self.assertIn('add @s5m_i4_41004 { ip daddr timeout 120s }', down[1])
        self.assertIn(' drop comment ', down[2])

    def test_tcp_only_table_setup_does_not_add_udp_output_chain(self):
        with mock.patch.object(core, 'cmd', side_effect=lambda args, **kw: None if '-j' in args else '') as command:
            core.ensure_tables()
        ip_batches = [call.kwargs['input'] for call in command.call_args_list
                      if call.kwargs.get('input', '').startswith('add table inet s5m_ip\n')]
        self.assertEqual(len(ip_batches), 1)
        self.assertNotIn('hook output', ip_batches[0])
        with mock.patch.object(core, 'nft_table', return_value=self.base('s5m_ip')), \
                mock.patch.object(core, 'execute_batch') as execute:
            core.ensure_udp_ip_output()
        self.assertEqual(execute.call_args.args[0], [
            'add chain inet s5m_ip outbound { type filter hook output priority -10; policy accept; }'])

    def test_failed_first_udp_cleanup_restores_tcp_only_chain_schema(self):
        snap = self.base('s5m_ip') + [
            {'chain': {'family': 'inet', 'table': 's5m_ip', 'name': 'outbound',
                       'type': 'filter', 'hook': 'output', 'prio': -10, 'policy': 'accept'}}]
        with mock.patch.object(core, 'delete_block', return_value=[]), \
                mock.patch.object(core, 'execute_batch') as execute, \
                mock.patch.object(core, 'systemctl'), mock.patch.object(core.Path, 'unlink'), \
                mock.patch.object(core.Path, 'rmdir'), mock.patch.object(core, 'nodes', return_value=[self.node]), \
                mock.patch.object(core, 'nft_table', return_value=snap):
            core.cleanup_udp(self.node)
        self.assertIn(mock.call(['delete chain inet s5m_ip outbound']), execute.call_args_list)
        other = {**self.node, 'id': 'other', 'instance': 'b' * 32, 'udp_range': [55100, 55163]}
        with mock.patch.object(core, 'delete_block', return_value=[]), \
                mock.patch.object(core, 'execute_batch') as execute, \
                mock.patch.object(core, 'systemctl'), mock.patch.object(core.Path, 'unlink'), \
                mock.patch.object(core.Path, 'rmdir'), mock.patch.object(core, 'nodes', return_value=[self.node, other]), \
                mock.patch.object(core, 'nft_table') as nft:
            core.cleanup_udp(self.node)
        self.assertNotIn(mock.call(['delete chain inet s5m_ip outbound']), execute.call_args_list)
        nft.assert_not_called()

    def test_destination_side_range_is_disjoint_and_keeps_largest_segment(self):
        node = {k: v for k, v in self.node.items() if k != 'udp_ext_range'}
        with mock.patch.object(core.Path, 'read_text', return_value='32768 60999'):
            self.assertEqual(core.udp_external_range(node), (32768, 54999))
            node['udp_range'] = [33000, 33063]
            self.assertEqual(core.udp_external_range(node), (33064, 60999))
        node['udp_ext_range'] = [33001, 33080]
        with self.assertRaises(core.Fail):core.udp_external_range(node)

    def test_full_quota_snapshot_and_semantic_negative_cases(self):
        snap = self.quota_snapshot()
        text = self.table_text(snap)
        self.assertTrue(core._nft_quota_ok(self.node, snap, text))
        for mutation in ('direction', 'range', 'quota', 'counter', 'owner', 'missing', 'order'):
            bad = copy.deepcopy(snap)
            target = next(x['rule'] for x in bad if x.get('rule', {}).get('comment', '').endswith('udpdropin'))
            if mutation == 'direction':target['expr'][1]['match']['right'] = 'reply'
            elif mutation == 'range':target['expr'][2]['match']['right']['range'][0] -= 1
            elif mutation == 'quota':target['expr'][-2]['quota'] = 'someone_else'
            elif mutation == 'counter':
                counter = next(x['rule'] for x in bad if x.get('rule', {}).get('comment', '').endswith('udpcountin'))
                counter['expr'][-1]['counter'] = 's5m_co_41004'
            elif mutation == 'owner':target['expr'][0]['match']['right'] = 's5u' + 'b' * 32 + '.slice'
            elif mutation == 'missing':bad.remove(next(x for x in bad if x.get('rule') is target))
            elif mutation == 'order':
                index = next(i for i, x in enumerate(bad) if x.get('rule') is target)
                bad[index], bad[index + 1] = bad[index + 1], bad[index]
            with self.subTest(mutation=mutation):self.assertFalse(core._nft_quota_ok(self.node, bad, self.table_text(bad)))

    def test_text_level_is_required_even_when_json_omits_it(self):
        for snap, validator in ((self.ip_snapshot(), core._nft_ip_ok),
                                (self.quota_snapshot(), core._nft_quota_ok)):
            self.assertTrue(validator(self.node, snap, self.table_text(snap)))
            self.assertFalse(validator(self.node, snap, self.table_text(snap, level=2)))
            self.assertFalse(validator(self.node, snap, self.table_text(snap).replace('"s5u', '"wrong-s5u')))

    def test_ip_refresh_cannot_use_destination_or_different_timeout(self):
        snap = self.ip_snapshot()
        self.assertTrue(core._nft_ip_ok(self.node, snap, self.table_text(snap)))
        bad = copy.deepcopy(snap)
        target = next(x['rule'] for x in bad if x.get('rule', {}).get('comment', '').endswith('udprefresh'))
        target['expr'][-2]['set']['elem']['val']['payload']['field'] = 'daddr'
        self.assertFalse(core._nft_ip_ok(self.node, bad, self.table_text(bad)))
        bad = copy.deepcopy(snap)
        target = next(x['rule'] for x in bad if x.get('rule', {}).get('comment', '').endswith('udpoutrefresh'))
        target['expr'][-2]['set']['elem']['val']['payload']['field'] = 'saddr'
        self.assertFalse(core._nft_ip_ok(self.node, bad, self.table_text(bad)))
        bad = copy.deepcopy(snap)
        bad = [x for x in bad if x.get('chain', {}).get('name') != 'outbound']
        self.assertFalse(core._nft_ip_ok(self.node, bad, self.table_text(bad)))
        bad = copy.deepcopy(snap)
        target = next(x['rule'] for x in bad if x.get('rule', {}).get('comment', '').endswith('udpclaim'))
        target['expr'][-2]['set']['elem']['timeout'] = 60
        self.assertFalse(core._nft_ip_ok(self.node, bad, self.table_text(bad)))

    def test_other_account_udp_rule_must_match_its_owner(self):
        other = copy.deepcopy(self.node)
        other.update(port=41005, instance='b' * 32, udp_range=[55100, 55163])
        snap = self.quota_snapshot()
        row = self.rule('s5m_quota', 'inbound', 'udpdropin',
                        udp_key(other) + [{'quota': 's5m_q_41005'}, {'drop': None}], other)
        snap.append(row)
        text = self.table_text(snap[:-1]) + '\n' + self.table_text([row], other)
        with mock.patch.object(core, 'nodes', return_value=[self.node, other]):
            self.assertTrue(core._nft_quota_ok(self.node, snap, text))
            row['rule']['expr'][0]['match']['right'] = 's5u' + self.node['instance'] + '.slice'
            self.assertFalse(core._nft_quota_ok(self.node, snap, text))

    def test_guard_requires_both_directions_and_final_fallback_drop(self):
        snap = self.guard_snapshot()
        with mock.patch.object(core.Path, 'is_dir', return_value=True), \
                mock.patch.object(core.Path, 'read_text', return_value=core._udp_dropin(self.node)):
            self.assertTrue(core._nft_udp_ok(self.node, snap, self.table_text(snap)))
            self.assertFalse(core._nft_udp_ok(self.node, snap[:-1], self.table_text(snap[:-1])))
            self.assertFalse(core._nft_udp_ok(self.node, snap, self.table_text(snap, level=2)))
            bad = copy.deepcopy(snap)
            bad[-1]['rule']['expr'][-1] = {'accept': None}
            self.assertFalse(core._nft_udp_ok(self.node, bad, self.table_text(bad)))

    def test_deadline_guard_matches_absolute_expiry_and_precedes_allows(self):
        with mock.patch.object(core, 'prepare_udp'), mock.patch.object(core, 'delete_block', return_value=[]), \
                mock.patch.object(core, 'execute_batch') as execute:
            core.apply_udp_guard(self.node)
        lines = execute.call_args.args[0]
        self.assertEqual(len(lines), 8)
        for offset in (0, 4):
            self.assertIn('meta time >= 2000000000 drop', lines[offset])
            self.assertIn('expiry"', lines[offset])
            self.assertIn(' accept comment ', lines[offset + 1])
        snap = self.guard_snapshot()
        with mock.patch.object(core.Path, 'is_dir', return_value=True), \
                mock.patch.object(core.Path, 'read_text', return_value=core._udp_dropin(self.node)):
            changed = {**self.node, 'expires': self.node['expires'] + 1}
            self.assertFalse(core._nft_udp_ok(changed, snap, self.table_text(snap)))
            late = copy.deepcopy(snap)
            expiry = next(x['rule'] for x in late if x.get('rule', {}).get('comment', '').endswith('inexpiry'))
            expiry['expr'][-2]['match']['right'] = '2033-05-18 03:33:21'
            self.assertFalse(core._nft_udp_ok(self.node, late, self.table_text(late)))

    def test_udp_run_uses_fractional_remaining_without_accepting_exit137(self):
        self.node['expires'] = 1001
        with mock.patch.object(core, 'node', return_value=self.node), mock.patch.object(core, 'ready', return_value=True), \
                mock.patch.object(core.time, 'time', return_value=1000.75), \
                mock.patch.object(core.Path, 'read_text', return_value='0::/' + core.udp_slice(self.node) + '/socks5.service'), \
                mock.patch.object(core, 'settings', return_value={'wan_if': 'eth0'}), \
                mock.patch.object(core, 'validate_iface'), mock.patch.object(core, 'local_route'), \
                mock.patch.object(core, 'verify_proxycfg'), mock.patch.object(core.os, 'execv', side_effect=SystemExit(0)) as execute:
            with self.assertRaises(SystemExit):
                core.operate(argparse.Namespace(action='run', id='lab'))
        args = execute.call_args.args[1]
        self.assertEqual(args[:3], ['timeout', '--foreground', '0.250000'])
        unit = core.make_units()['socks5-@.service']
        self.assertNotIn('SuccessExitStatus=0 124 137', unit)
        self.assertIn('SuccessExitStatus=0 124 143', unit)

    def test_nft_time_rendering_is_pinned_to_utc_without_global_env_change(self):
        result = types.SimpleNamespace(returncode=0, stdout='ok', stderr='')
        with mock.patch.dict(core.os.environ, {'TZ': 'Asia/Shanghai'}), \
                mock.patch.object(core.subprocess, 'run', return_value=result) as run:
            core.cmd(['nft', '-j', 'list', 'table', 'inet', 's5m_udp'])
            self.assertEqual(run.call_args.kwargs['env']['TZ'], 'UTC')
            self.assertEqual(core.os.environ['TZ'], 'Asia/Shanghai')
        self.assertEqual(core._udp_deadline_json(self.node), '2033-05-18 03:33:20')

    def test_shutdown_saves_before_proxy_and_slice_stop_without_ordering_cycle(self):
        units = core.make_units()
        def unit_order(body, name):
            section = None
            values = []
            for line in body.splitlines():
                if line.startswith('['):section = line
                elif section == '[Unit]' and line.startswith(name + '='):
                    values.extend(line.split('=', 1)[1].split())
            return values
        proxy = 'socks5-@.service'
        quota_save = 'socks5-shutdown.service'
        traffic_save = 'socks5-traffic-shutdown.service'
        root_slice = core.udp_slice(self.node)
        units[root_slice] = core._udp_slice_unit()
        self.assertIn(quota_save, unit_order(units[proxy], 'Before'))
        self.assertIn(traffic_save, unit_order(units[proxy], 'Before'))
        self.assertIn(quota_save, unit_order(units[root_slice], 'Before'))
        self.assertIn(traffic_save, unit_order(units[root_slice], 'Before'))
        self.assertIn('nftables.service', unit_order(units[quota_save], 'After'))
        edges = {}
        def edge(first, second):
            edges.setdefault(first, set()).add(second)
            edges.setdefault(second, set())
        for name, body in units.items():
            for target in unit_order(body, 'Before'):edge(name, target)
            for target in unit_order(body, 'After'):edge(target, name)
        # systemd gives service units an implicit After= on their Slice=.
        edge(root_slice, proxy)
        visiting, visited, ordered = set(), set(), []
        def visit(name):
            self.assertNotIn(name, visiting, 'unit ordering cycle at ' + name)
            if name in visited:return
            visiting.add(name)
            for target in edges[name]:visit(target)
            visiting.remove(name)
            visited.add(name)
            ordered.append(name)
        for name in edges:visit(name)
        # DFS postorder is the stop order (reverse of startup order).
        for snapshot in (quota_save, traffic_save):
            self.assertLess(ordered.index(snapshot), ordered.index(proxy))
            self.assertLess(ordered.index(snapshot), ordered.index(root_slice))
        self.assertLess(ordered.index(quota_save), ordered.index('nftables.service'))
        # Even an already stopped proxy has no stop job; its persistent slice
        # must still be ordered after both snapshots in the stop transaction.
        inactive_edges = {name: {target for target in targets if target != proxy}
                          for name, targets in edges.items() if name != proxy}
        self.assertIn(quota_save, inactive_edges[root_slice])
        self.assertIn(traffic_save, inactive_edges[root_slice])

    def test_udp_json_normalization_is_narrow_and_malformed_is_false(self):
        expected = core.udp_client_expr(self.node, 'input') + [{'counter': 'daily_up'}]
        actual = udp_key(self.node) + [{'counter': 'daily_up'}]
        self.assertTrue(core._udp_expr_equal(actual, expected))
        self.assertFalse(core._udp_expr_equal(actual + [{'accept': None}], expected))
        for bad in ([None], [{'match': {'left': 'wrong'}}], [{'match': {'left': {'socket': None}}}]):
            self.assertFalse(core._udp_expr_equal(bad, expected))
        bad = copy.deepcopy(actual)
        bad[0]['match']['left']['socket']['level'] = 2
        self.assertFalse(core._udp_expr_equal(bad, expected))

    def test_missing_udp_guard_fails_ready_but_legacy_tcp_still_works(self):
        snaps = {core.TABLE_IP: self.ip_snapshot(), core.TABLE_Q: self.quota_snapshot()}
        for table in (core.TABLE_IP, core.TABLE_Q):snaps[table + '_text'] = self.table_text(snaps[table])
        self.assertFalse(core.ready(self.node, snaps))
        legacy = {k: v for k, v in self.node.items() if k != 'udp_range'}
        self.assertTrue(core.ready(legacy, {core.TABLE_IP: self.ip_snapshot(False),
                                            core.TABLE_Q: self.quota_snapshot(False)}))

    def test_healthcheck_rejects_wrong_password_udp_even_with_outside_reply_port(self):
        node = self.node
        class Peer:
            def __init__(self, evil=False):
                self.stage = 0
                self.pending = b''
                self.correct = False
                self.evil = evil
            def settimeout(self, value):pass
            def close(self):pass
            def sendall(self, data):
                if self.stage == 0:
                    self.pending = b'\x05\x02'
                elif self.stage == 1:
                    offset = 2 + data[1]
                    self.correct = data[offset + 1:] == node['password'].encode()
                    # 3proxy may defer actual credential checking to the command.
                    self.pending = b'\x01\x00'
                elif data[1] == 3:
                    accepted = self.correct or self.evil
                    relay = 55000 if self.correct else 65000
                    self.pending = bytes([5, 0 if accepted else 2, 0, 1]) + b'\x7f\x00\x00\x01' + relay.to_bytes(2, 'big')
                else:
                    allowed = self.correct and data[4:8] == b'\x01\x01\x01\x01'
                    self.pending = bytes([5, 0 if allowed else 2])
                self.stage += 1
            def recv(self, count):
                result, self.pending = self.pending[:count], self.pending[count:]
                return result
        with mock.patch.object(core.socket, 'create_connection', side_effect=lambda *a, **k: Peer()):
            core.socks_handshake(node)
        with mock.patch.object(core.socket, 'create_connection', side_effect=lambda *a, **k: Peer(True)):
            with self.assertRaisesRegex(core.Fail, '错误密码可以 UDP ASSOCIATE'):
                core.socks_handshake(node)


if __name__ == '__main__':
    unittest.main()
