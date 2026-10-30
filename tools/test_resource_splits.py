#!/usr/bin/env python3
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from resource_splits import merge_resources, validate_split, verify_payload
from test_assemble import make_zip, manifest


class ResourceSplitTests(unittest.TestCase):
    def test_payload_changes_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            items = {'AndroidManifest.xml': manifest(), 'classes.dex': b'patched',
                     'lib/arm64-v8a/libg.so': b'native', 'assets/data': b'data',
                     'META-INF/services/dispatcher': b'kotlin'}
            base, output = root/'base.apk', root/'output.apk'
            make_zip(base, items)
            for name in list(items)[1:]:
                changed = dict(items); changed[name] = b'changed'
                make_zip(output, changed)
                with self.assertRaisesRegex(ValueError, 'changed runtime payload'):
                    verify_payload(base, output)
            make_zip(output, dict(items, **{'resources.arsc': b'new table'}))
            verify_payload(base, output)

    def test_wrong_split_version_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('base', 'split'):
                make_zip(root/(name+'.apk'), {'AndroidManifest.xml': manifest(), 'resources.arsc': b'table'})
            with patch('resource_splits.manifest_root', side_effect=[
                    (None, {'package': 'game', 'versionCode': 1}),
                    (None, {'package': 'game', 'versionCode': 2, 'split': 'config.xxhdpi'})]):
                with self.assertRaisesRegex(ValueError, 'package/version mismatch'):
                    validate_split(root/'base.apk', root/'split.apk')

    def test_resource_merge_preserves_payload_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); base, output = root/'base.apk', root/'output.apk'
            make_zip(base, {'AndroidManifest.xml': manifest(), 'resources.arsc': b'old',
                            'res/old.xml': b'old', 'classes.dex': b'patched',
                            'META-INF/services/dispatcher': b'kotlin'})
            editor = root/'editor.jar'; editor.touch()
            def run(command):
                make_zip(Path(command[command.index('-o')+1]),
                         {'resources.arsc': b'merged', 'res/restored.png': b'bitmap',
                          'AndroidManifest.xml': b'not used', 'classes.dex': b'never copy'})
            merge_resources(base, [], output, editor, run)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.read('resources.arsc'), b'merged')
                self.assertEqual(archive.read('res/restored.png'), b'bitmap')
                self.assertEqual(archive.read('classes.dex'), b'patched')
                self.assertEqual(archive.read('AndroidManifest.xml'), manifest())
                self.assertEqual(archive.read('META-INF/services/dispatcher'), b'kotlin')


if __name__ == '__main__':
    unittest.main()
