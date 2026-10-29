#!/usr/bin/env python3
import hashlib
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import test_v66_release as release
import test_release as generic


class RunnerTests(unittest.TestCase):
    def test_generic_coverage(self):
        self.assertEqual(generic.coverage('Patched: 7/7 groups, 91 fields, 113 strings,\n'),
                         {'groups': 7, 'fields': 91, 'strings': 113})
        for log in ('', 'Patched: 6/7 groups, 91 fields, 113 strings,\n',
                    'Patched: 0/0 groups, 0 fields, 0 strings,\n'):
            with self.assertRaises(ValueError):
                generic.coverage(log)

    def test_generic_config_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / 'base.apk'
            with zipfile.ZipFile(base, 'w') as archive:
                archive.writestr('assets/unpredictable-name.bin', b'lbtsfixture')
                archive.writestr('assets/decoy.dat', b'not a config')
            self.assertEqual(generic.extract_config(base, root).read_bytes(), b'lbtsfixture')
            with zipfile.ZipFile(base, 'a') as archive:
                archive.writestr('assets/ambiguous.bin', b'lbtsanother')
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                generic.extract_config(base, root)

    def test_context_capture_without_retained_files(self):
        root = Path('/nonexistent/test with spaces')
        candidate = str(root / 'tmp/8nomorp-context-unique/ctx_123_0.bin')
        log = '[+] context candidate: ' + candidate + ' (entry 0x123, copy site 0x456)\n'
        self.assertEqual(release.context_captures(log, root), [candidate])
        with self.assertRaisesRegex(ValueError, 'private test directory'):
            release.context_captures(log, Path('/another/test'))
        with self.assertRaisesRegex(ValueError, 'no freshly generated'):
            release.context_captures('', root)

    def test_fixture_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = {name: Path(tmp) / name for name in release.FIXTURE_HASHES}
            for name, path in paths.items():
                path.write_bytes(name.encode())
            expected = {name: hashlib.sha256(name.encode()).hexdigest() for name in paths}
            with patch.object(release, 'FIXTURE_HASHES', expected):
                release.validate_inputs(paths)
                paths['shield'].write_bytes(b'wrong build')
                with self.assertRaisesRegex(ValueError, 'shield'):
                    release.validate_inputs(paths)

    def test_failed_subprocess_retains_log(self):
        import os
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, 'step failed'):
                release.run([sys.executable, '-c', 'print("diagnostic"); exit(3)'],
                            root, 'step', os.environ.copy())
            self.assertIn('diagnostic', (root / 'step.log').read_text())


if __name__ == '__main__':
    unittest.main()
