import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import gfwlist_parser as parser


class MrsDomainTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.rules = [
            'DOMAIN,exact.example.com',
            'DOMAIN-SUFFIX,example.net',
            'DOMAIN-KEYWORD,colab',
            'DOMAIN-REGEX,^test.*',
            'IP-CIDR,192.0.2.0/24,no-resolve',
        ]

    def test_split_list_preserves_domain_semantics(self):
        source = self.root / 'test.list'
        original = '\n'.join(self.rules) + '\n'
        source.write_text(original)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            parser.split_list_file(str(source))
        self.assertEqual((self.root / 'test_domain.list').read_text(),
                         '+.example.net\nexact.example.com\n')
        self.assertEqual((self.root / 'test_ip.list').read_text(), '192.0.2.0/24\n')
        self.assertEqual(source.read_text(), original)
        self.assertIn('DOMAIN-KEYWORD', output.getvalue())
        self.assertIn('DOMAIN-REGEX', output.getvalue())

    def test_split_yaml_preserves_domain_semantics(self):
        source = self.root / 'test.yaml'
        original = 'payload:\n' + ''.join(f'  - {r}\n' for r in self.rules)
        source.write_text(original)
        with contextlib.redirect_stdout(io.StringIO()):
            parser.split_yaml_file(str(source))
        self.assertEqual((self.root / 'test_domain.yaml').read_text(),
                         'payload:\n  - +.example.net\n  - exact.example.com\n')
        self.assertEqual((self.root / 'test_ip.yaml').read_text(),
                         'payload:\n  - 192.0.2.0/24\n')
        self.assertEqual(source.read_text(), original)

    def test_gfwlist_generators_write_domain_payloads(self):
        yaml = self.root / 'generated.yaml'
        text = self.root / 'generated.list'
        domains = ['example.net', 'example.net']
        parser.generate_clash_provider_yaml(domains, [], str(yaml))
        parser.generate_clash_ruleset_list(domains, [], str(text))
        self.assertIn('DOMAIN-SUFFIX,example.net', yaml.read_text())
        self.assertIn('DOMAIN-SUFFIX,example.net', text.read_text())
        self.assertEqual((self.root / 'generated_domain.yaml').read_text(),
                         'payload:\n  - +.example.net\n')
        self.assertEqual((self.root / 'generated_domain.list').read_text(),
                         '+.example.net\n')

    def test_unsupported_rules_are_not_reinterpreted_as_domains(self):
        for suffix, split in [('list', parser.split_list_file),
                              ('yaml', parser.split_yaml_file)]:
            source = self.root / f'unsupported.{suffix}'
            source.write_text('DOMAIN-KEYWORD,colab\n' if suffix == 'list'
                              else 'payload:\n  - DOMAIN-KEYWORD,colab\n')
            with contextlib.redirect_stdout(io.StringIO()):
                split(str(source))
            self.assertFalse((self.root / f'unsupported_domain.{suffix}').exists())

    @unittest.skipUnless(os.environ.get('MIHOMO_BIN'), 'MIHOMO_BIN is not set')
    def test_mihomo_roundtrip_for_yaml_and_text(self):
        for suffix, format, split in [('list', 'text', parser.split_list_file),
                                      ('yaml', 'yaml', parser.split_yaml_file)]:
            source = self.root / f'roundtrip.{suffix}'
            source.write_text('\n'.join(self.rules) + '\n' if suffix == 'list'
                              else 'payload:\n' + ''.join(f'  - {r}\n' for r in self.rules))
            with contextlib.redirect_stdout(io.StringIO()):
                split(str(source))
            mrs = self.root / f'{format}.mrs'
            decoded = self.root / f'{format}.txt'
            subprocess.run([os.environ['MIHOMO_BIN'], 'convert-ruleset', 'domain', format,
                            str(self.root / f'roundtrip_domain.{suffix}'), str(mrs)],
                           check=True, capture_output=True)
            subprocess.run([os.environ['MIHOMO_BIN'], 'convert-ruleset', 'domain', 'mrs',
                            str(mrs), str(decoded)], check=True, capture_output=True)
            self.assertEqual(set(decoded.read_text().splitlines()),
                             {'+.example.net', 'exact.example.com'})


if __name__ == '__main__':
    unittest.main()
