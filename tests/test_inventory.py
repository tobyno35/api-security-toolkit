import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from api_security_toolkit.inventory import Scope, EvidenceError, build, candidates, endpoint, host, markdown, records, publish, main

FIX = Path(__file__).resolve().parents[1] / 'fixtures' / 'inventory'


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(json.loads((FIX / 'allowlist.json').read_text()))
        self.inputs = [('subfinder', FIX / 'subfinder.jsonl'), ('dnsx', FIX / 'dnsx.json'), ('httpx', FIX / 'httpx.jsonl')]

    def test_fixture_inventory_and_provenance(self):
        report = build(self.scope, self.inputs)
        self.assertEqual(len(report['assets']), 5)
        self.assertEqual(len(report['rejected']), 3)
        domain = next(x for x in report['assets'] if x['kind'] == 'domain')
        self.assertEqual(domain['value'], 'api.example.test')
        self.assertEqual(len(domain['references']), 5)
        for asset in report['assets']:
            self.assertTrue(self.scope.permits(asset['kind'], asset['value']))
            for ref in asset['references']:
                self.assertIn(ref['source'], report['sources'])
                self.assertGreater(ref['record'], 0)

    def test_deterministic_order_and_duplicate_files(self):
        expected = build(self.scope, self.inputs)
        self.assertEqual(expected, build(self.scope, list(reversed(self.inputs)) + self.inputs))
        self.assertEqual(markdown(expected), markdown(build(self.scope, self.inputs)))

    def test_wildcard_boundaries(self):
        scope = Scope({'domains': ['*.example.test'], 'networks': [], 'endpoints': []})
        for name in ['example.test', 'evilexample.test', 'example.test.evil.test']:
            self.assertFalse(scope.permits('domain', name))
        self.assertTrue(scope.permits('domain', 'a.b.example.test'))

    def test_endpoint_requires_exact_url_and_host(self):
        for url in ['http://api.example.test/', 'https://api.example.test:8443/', 'https://api.example.test/admin', 'https://api.example.test/?admin=1']:
            self.assertFalse(self.scope.permits('endpoint', endpoint(url)[0]))
        scope = Scope({'domains': [], 'networks': [], 'endpoints': ['https://api.example.test/']})
        self.assertFalse(scope.permits('endpoint', 'https://api.example.test/'))

    def test_invalid_hosts(self):
        for name in ['a.example.test\n', 'a..example.test', '*.example.test', '-a.example.test', '127.1', '2130706433', '0177.0.0.1', 'é.example.test', 'a.example.test/']:
            with self.subTest(name=name), self.assertRaises(EvidenceError):
                host(name)

    def test_invalid_urls(self):
        for url in ['file:///etc/passwd', 'https://user@api.example.test/', 'https://api.example.test/#frag', 'https://api.example.test:0/', 'https://api.example.test:65536/', 'https://api.example.test\\@evil.test/', ' https://api.example.test/', 'https://api.example.test/\n']:
            with self.subTest(url=url), self.assertRaises(EvidenceError):
                endpoint(url)

    def test_canonicalization(self):
        self.assertEqual(endpoint('https://API.EXAMPLE.TEST.:443')[0], 'https://api.example.test/')
        self.assertEqual(host('2001:0db8:0:0::10'), ('ip', '2001:db8::10'))
        self.assertEqual(endpoint('http://[2001:db8::10]:80')[0], 'http://[2001:db8::10]/')

    def test_bad_allowlists(self):
        for data in [{}, {'domains': '*', 'networks': [], 'endpoints': []}, {'domains': ['*'], 'networks': [], 'endpoints': []}, {'domains': [], 'networks': ['192.0.2.1/24'], 'endpoints': []}, {'domains': [], 'networks': [], 'endpoints': [], 'extra': []}]:
            with self.subTest(data=data), self.assertRaises(EvidenceError):
                Scope(data)

    def test_json_rejection(self):
        for raw in [b'', b'null', b'[]', b'[1]', b'{"host":"a","host":"b"}', b'{"n":NaN}', b'{bad']:
            with self.subTest(raw=raw), self.assertRaises(EvidenceError):
                records(raw)

    def test_bad_record_shapes(self):
        for row in [{}, {'host': 7}, {'host': 'api.example.test', 'a': '192.0.2.1'}, {'host': 'api.example.test', 'a': ['outside.test']}]:
            with self.subTest(row=row), self.assertRaises(EvidenceError):
                candidates('dnsx', row)

    def test_record_quarantine_and_no_scope_inheritance(self):
        rows = [
            ('dnsx', {'host': 'api.example.test', 'a': ['203.0.113.1']}),
            ('dnsx', {'host': 'outside.test', 'a': ['192.0.2.1']}),
            ('dnsx', {'host': 'api.example.test', 'cname': ['outside.test']}),
            ('httpx', {'url': 'https://api.example.test/', 'final_url': 'https://outside.test/'}),
            ('httpx', {'url': 'https://api.example.test/', 'location': '/relative'}),
            ('dnsx', {'host': 'api.example.test', 'a': 1}),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'data.json'
            for tool, row in rows:
                path.write_text(json.dumps(row))
                report = build(self.scope, [(tool, path)])
                self.assertEqual(report['assets'], [])
                self.assertEqual(len(report['rejected']), 1)

    def test_optional_urls_reject_every_malformed_present_value(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'httpx.json'
            for key in ('final_url', 'location'):
                for value in (None, False, 0, [], ['https://api.example.test/'], {}, '', True):
                    with self.subTest(key=key, value=value):
                        path.write_text(json.dumps({'url': 'https://api.example.test/', key: value}))
                        report = build(self.scope, [('httpx', path)])
                        self.assertEqual(report['assets'], [])
                        self.assertEqual(report['rejected'][0]['reason'], 'invalid_record')
            for row in ({'url': 'https://api.example.test/'},
                        {'url': 'https://api.example.test/', 'location': 'https://api.example.test/'}):
                self.assertTrue(candidates('httpx', row))

    def test_empty_fragment_rejected_in_rules_and_evidence(self):
        for url in ('https://api.example.test/#', 'https://api.example.test/?#'):
            with self.subTest(url=url):
                with self.assertRaises(EvidenceError):
                    endpoint(url)
                with self.assertRaises(EvidenceError):
                    Scope({'domains': ['api.example.test'], 'networks': [], 'endpoints': [url]})
                with self.assertRaises(EvidenceError):
                    candidates('httpx', {'url': url})

    def test_empty_query_is_exact_scope_not_removed(self):
        plain, query = 'https://api.example.test/', 'https://api.example.test/?'
        self.assertEqual(endpoint(query)[0], query)
        self.assertEqual(endpoint('https://API.EXAMPLE.TEST:443?')[0], query)
        for allowed, denied in ((plain, query), (query, plain)):
            scope = Scope({'domains': ['api.example.test'], 'networks': [], 'endpoints': [allowed]})
            self.assertTrue(scope.permits('endpoint', endpoint(allowed)[0]))
            self.assertFalse(scope.permits('endpoint', endpoint(denied)[0]))
        self.assertEqual(endpoint('https://api.example.test/%23?x=%3F')[0],
                         'https://api.example.test/%23?x=%3F')

    def test_publication_failures_never_look_complete(self):
        report = build(self.scope, self.inputs)
        original_write, original_replace = Path.write_text, Path.replace
        for operation, name in (('write', 'inventory.json'), ('write', 'inventory.md'),
                                ('replace', 'inventory.json'), ('replace', 'inventory.md')):
            with self.subTest(operation=operation, name=name), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'report'
                def fail_write(path, *args, **kwargs):
                    if path.name == name:
                        original_write(path, 'partial', encoding='utf-8')
                        raise OSError('injected write failure')
                    return original_write(path, *args, **kwargs)
                def fail_replace(path, *args, **kwargs):
                    if path.name == name:
                        raise OSError('injected publication failure')
                    return original_replace(path, *args, **kwargs)
                with patch.object(Path, 'write_text' if operation == 'write' else 'replace',
                                  fail_write if operation == 'write' else fail_replace):
                    with self.assertRaises(OSError):
                        publish(report, output)
                self.assertTrue((output / '.inventory-incomplete').is_dir())
                if operation == 'write':
                    self.assertFalse((output / 'inventory.json').exists())
                    self.assertFalse((output / 'inventory.md').exists())
                with self.assertRaises(FileExistsError):
                    publish(report, output)

    def test_marker_removal_failure_keeps_complete_files_unpublished(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'report'
            original = Path.rmdir
            def fail_marker(path):
                if path.name == '.inventory-incomplete':
                    raise OSError('injected marker failure')
                return original(path)
            with patch.object(Path, 'rmdir', fail_marker), self.assertRaises(OSError):
                publish(build(self.scope, self.inputs), output)
            self.assertTrue((output / '.inventory-incomplete').is_dir())
            self.assertTrue((output / 'inventory.json').is_file())
            self.assertTrue((output / 'inventory.md').is_file())

    def test_interrupted_write_keeps_incomplete_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'report'
            with patch.object(Path, 'write_text', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                publish(build(self.scope, self.inputs), output)
            self.assertTrue((output / '.inventory-incomplete').is_dir())
            self.assertFalse((output / 'inventory.json').exists())

    def test_cli_publication_failure_exit_and_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'report'
            argv = ['inventory', '--allowlist', str(FIX / 'allowlist.json'),
                    '--subfinder', str(FIX / 'subfinder.jsonl'), '--output', str(output)]
            with patch('sys.argv', argv), patch.object(Path, 'write_text', side_effect=OSError('disk full')):
                with self.assertRaises(SystemExit) as error:
                    main()
            self.assertEqual(error.exception.code, 2)
            self.assertTrue((output / '.inventory-incomplete').exists())

    def test_no_network(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            build(self.scope, self.inputs)

    def test_markdown_escapes_evidence(self):
        report = {'assets': [{'kind': 'endpoint', 'value': '<script>|`', 'references': []}], 'rejected': []}
        text = markdown(report)
        self.assertNotIn('<script>', text)
        self.assertIn('&#124;', text)
        self.assertIn('&#96;', text)

    def test_cli_reports_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'report'
            cmd = [sys.executable, '-m', 'api_security_toolkit.inventory', '--allowlist', str(FIX / 'allowlist.json'), '--subfinder', str(FIX / 'subfinder.jsonl'), '--output', str(output)]
            run = subprocess.run(cmd, capture_output=True)
            self.assertEqual(run.returncode, 1, run.stderr)
            self.assertTrue((output / 'inventory.md').exists())
            self.assertFalse((output / '.inventory-incomplete').exists())
            self.assertEqual(len(json.loads((output / 'inventory.json').read_text())['rejected']), 1)
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 2)


if __name__ == '__main__':
    unittest.main()
