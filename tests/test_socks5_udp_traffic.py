"""UDP daily-history regression tests; run on Linux with the manager module."""
import copy
import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


core = module('socks5', 'socks5.py')
traffic = module('s5_udp_daily_test', 'socks5-traffic.py')


class UdpDailyHistoryTests(unittest.TestCase):
    def setUp(self):
        self.node = {'id': 'lab', 'port': 49151, 'instance': 'a' * 32,
                     'username': 'test', 'created': 100, 'expires': 9999999999}

    def current(self, udp=True):
        node = copy.deepcopy(self.node)
        if udp:
            node['udp_range'] = [55000, 55063]
        with patch.object(traffic, 'nodes', return_value=[node]):
            return traffic.active_nodes(1000)

    def snapshot(self, current):
        snap = [{'table': {'name': traffic.TABLE}}]
        selected = {}
        counts = {}
        for chain in ('input', 'output'):
            snap.append({'chain': {'name': chain, 'type': 'filter', 'hook': chain,
                                   'prio': 10, 'policy': 'accept'}})
        for tag, node in current.items():
            for direction, chain in [('u', 'input'), ('d', 'output')]:
                name = f't_{node["key"]}_{"b" * 16}_{direction}'
                selected[tag, direction] = name
                counts[name] = 123456
                snap.append({'counter': {'name': name, 'bytes': 123456}})
                field = 'dport' if chain == 'input' else 'sport'
                tcp = [{'match': {'op': '==', 'left': {'payload': {
                    'protocol': 'tcp', 'field': field}}, 'right': node['port']}},
                       {'counter': name}]
                snap.append({'rule': {'chain': chain, 'comment': name, 'expr': tcp}})
                if core.udp_range(node):
                    udp = core.udp_client_expr(node, chain) + [{'counter': name}]
                    snap.append({'rule': {'chain': chain, 'comment': name, 'expr': udp}})
        return snap, selected, counts

    def test_udp_metadata_keeps_existing_history_identity(self):
        before = self.current(False)['lab']
        after = self.current(True)['lab']
        self.assertEqual(before['key'], after['key'])
        self.assertEqual(after['udp_range'], [55000, 55063])

    def test_existing_tcp_counter_is_shared_with_udp(self):
        current = self.current()
        snapshot, selected, counts = self.snapshot(current)
        snapshot = [x for x in snapshot if 'rule' not in x or
                    not any('socket' in str(e) for e in x['rule']['expr'])]
        commands = traffic.reconcile(current, selected, snapshot, counts)
        self.assertEqual(sum('add rule' in x for x in commands), 4)
        self.assertFalse(any('add counter' in x or 'delete counter' in x for x in commands))
        for name in counts:
            self.assertEqual(sum(f'counter name {name} ' in x for x in commands), 2)

    def test_repeated_collect_does_not_flush_valid_udp_rules(self):
        current = self.current()
        snapshot, selected, counts = self.snapshot(current)
        self.assertEqual(traffic.reconcile(current, selected, snapshot, counts), [])

    def test_damaged_udp_expression_is_repaired_without_resetting_history(self):
        current = self.current()
        snapshot, selected, counts = self.snapshot(current)
        udp = next(x['rule'] for x in snapshot if 'rule' in x and
                   any('socket' in str(e) for e in x['rule']['expr']))
        udp['expr'] = [{'accept': None}]
        commands = traffic.reconcile(current, selected, snapshot, counts)
        self.assertTrue(any('flush chain' in x for x in commands))
        self.assertFalse(any('add counter' in x or 'delete counter' in x for x in commands))

    def test_tcp_only_rule_count_and_counter_names_are_unchanged(self):
        current = self.current(False)
        snapshot, selected, counts = self.snapshot(current)
        self.assertEqual(sum('rule' in x for x in snapshot), 2)
        self.assertEqual(traffic.reconcile(current, selected, snapshot, counts), [])


if __name__ == '__main__':
    unittest.main()
