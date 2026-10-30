#!/usr/bin/env python3
import argparse
import struct
import tempfile
import unittest
from pathlib import Path
import zipfile
from unittest.mock import patch

import assemble as apk
from games import GAMES, SHIELDS, shield_for


def manifest(utf8=False, package='com.supercell.brawlstars'):
    names = ['manifest', 'package', 'versionCode', 'requiredSplitTypes', 'splitTypes',
             package, 'base__abi,base__density', '']
    body = bytearray()
    offsets = []
    for name in names:
        offsets.append(len(body))
        if utf8:
            encoded = name.encode()
            body.extend(bytes([len(name), len(encoded)]) + encoded + b'\0')
        else:
            body.extend(struct.pack('<H', len(name)) + name.encode('utf-16-le') + b'\0\0')
    while len(body) % 4:
        body.append(0)
    pool_size = 28 + 4 * len(names) + len(body)
    pool = struct.pack('<HH6I', 1, 28, pool_size, len(names), 0, 0x100 if utf8 else 0, 28 + 4 * len(names), 0)
    pool += struct.pack('<%dI' % len(names), *offsets) + body
    attrs = b''
    for name, kind, value in [(1, 3, 5), (2, 16, 67306), (3, 3, 6), (4, 3, 7)]:
        attrs += struct.pack('<IIIHBBI', 0xffffffff, name, 0xffffffff, 8, 0, kind, value)
    element = struct.pack('<HHIII', 0x102, 16, 36 + len(attrs), 1, 0xffffffff)
    # Deliberately exercise one-based id/class/style attribute indexes.
    element += struct.pack('<II6H', 0xffffffff, 0, 20, 20, 4, 1, 3, 4) + attrs
    return struct.pack('<HHI', 3, 8, 8 + len(pool) + len(element)) + pool + element


def make_zip(path, items):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, value in items.items():
            z.writestr(name, value)


class AssemblyTests(unittest.TestCase):
    def test_apk_uses_zip32_not_pythons_conservative_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            with patch.object(zipfile, 'ZIP64_LIMIT', 64):
                apk.assemble(args)
                self.assertEqual(zipfile.ZIP64_LIMIT, 64)
            data = args.output.read_bytes()
            self.assertNotIn(b'PK\x06\x06', data)
            with zipfile.ZipFile(args.output) as z:
                self.assertEqual(z.read(apk.LIBRARY), b'unpacked')

    def test_supported_shields_only(self):
        for package in GAMES:
            self.assertIn(shield_for(package), SHIELDS)
        with self.assertRaises(ValueError):
            shield_for('com.example.unknown')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.fixture(root)
            with zipfile.ZipFile(args.native_split, 'a') as z:
                for name in SHIELDS:
                    z.writestr(name, b'shield')
            apk.assemble(args)
            with zipfile.ZipFile(args.output) as z:
                self.assertFalse(SHIELDS.intersection(z.namelist()))

    def test_manifest_utf8_utf16_and_indexes(self):
        for utf8 in (False, True):
            data = manifest(utf8)
            out = apk.standalone_manifest(data)
            _, attrs, (_, ext, _, _, count) = apk.manifest_root(out)
            self.assertEqual(len(out), len(data) - 20)
            self.assertNotIn('requiredSplitTypes', attrs)
            self.assertEqual(attrs['package'], 'com.supercell.brawlstars')
            self.assertEqual(attrs['versionCode'], 67306)
            self.assertEqual(count, 3)
            self.assertEqual(struct.unpack_from('<3H', out, ext + 14), (1, 0, 3))
            self.assertEqual(apk.standalone_manifest(out), out)

    def test_invalid_manifest(self):
        for data in (b'', b'not axml', manifest()[:-1]):
            with self.assertRaises(ValueError):
                apk.standalone_manifest(data)

    def fixture(self, root):
        args = argparse.Namespace(**{name: root / (name + '.bin') for name in
                                      ('original_base', 'base', 'native_split', 'asset_pack', 'library')})
        args.base = root / 'patched.apk'
        args.output = root / 'out.apk'
        base = {'AndroidManifest.xml': manifest(), 'classes.dex': b'original',
                'resources.arsc': b'compiled resources', 'assets/config.dat': b'config'}
        make_zip(args.original_base, base)
        make_zip(args.base, dict(base, **{'classes.dex': b'patched', 'META-INF/OLD.RSA': b'old signature'}))
        make_zip(args.native_split, {'AndroidManifest.xml': manifest(), apk.LIBRARY: b'packed',
                                    'lib/arm64-v8a/libother.so': b'dependency'})
        make_zip(args.asset_pack, {'assets/fingerprint.json': b'{}', 'assets/csv_logic/test.csv': b'content',
                                   'AndroidManifest.xml': b'split manifest'})
        args.library.write_bytes(b'unpacked')
        return args

    def test_complete_merge_and_compression(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            apk.assemble(args)
            with zipfile.ZipFile(args.output) as z:
                self.assertEqual(z.read(apk.LIBRARY), b'unpacked')
                self.assertEqual(z.read('classes.dex'), b'patched')
                self.assertEqual(z.read('assets/csv_logic/test.csv'), b'content')
                self.assertEqual(z.read('lib/arm64-v8a/libother.so'), b'dependency')
                self.assertEqual(z.getinfo('resources.arsc').compress_type, zipfile.ZIP_STORED)
                self.assertNotIn('META-INF/OLD.RSA', z.namelist())
                self.assertNotIn('requiredSplitTypes', apk.manifest_root(z.read('AndroidManifest.xml'))[1])
            saved = args.output.read_bytes()
            with self.assertRaises(FileExistsError):
                apk.assemble(args)
            self.assertEqual(args.output.read_bytes(), saved)

    def test_original_service_metadata_survives_apktool(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            service = 'META-INF/services/kotlinx.coroutines.internal.MainDispatcherFactory'
            provider = b'kotlinx.coroutines.android.AndroidDispatcherFactory\n'
            with zipfile.ZipFile(args.original_base, 'a') as z:
                z.writestr(service, provider)
                z.writestr('META-INF/ORIGINAL.RSA', b'old signature')
            apk.assemble(args)
            with zipfile.ZipFile(args.output) as z:
                self.assertEqual(z.read(service), provider)
                self.assertNotIn('META-INF/ORIGINAL.RSA', z.namelist())

    def test_unknown_build_metadata_is_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            apk.assemble(args)
            with zipfile.ZipFile(args.output) as z:
                self.assertNotIn('requiredSplitTypes', apk.manifest_root(z.read('AndroidManifest.xml'))[1])

    def test_changed_resources_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            make_zip(args.base, {'AndroidManifest.xml': manifest(), 'classes.dex': b'patched', 'resources.arsc': b'changed'})
            with self.assertRaisesRegex(ValueError, 'changed original resources'):
                apk.assemble(args)
            self.assertFalse(args.output.exists())

    def test_conflicting_and_duplicate_entries_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.fixture(root)
            with zipfile.ZipFile(args.base, 'a') as z:
                z.writestr('assets/fingerprint.json', b'conflict')
            with zipfile.ZipFile(args.base) as b, zipfile.ZipFile(args.native_split) as n, zipfile.ZipFile(args.asset_pack) as a:
                with self.assertRaisesRegex(ValueError, 'conflicting ZIP'):
                    apk.plan(b, n, a)
            make_zip(root / 'dup.zip', {'x': b'1'})
            import warnings
            with warnings.catch_warnings(), zipfile.ZipFile(root / 'dup.zip', 'a') as z:
                warnings.simplefilter('ignore')
                z.writestr('x', b'2')
            with zipfile.ZipFile(root / 'dup.zip') as z, self.assertRaisesRegex(ValueError, 'duplicate ZIP'):
                apk.entries(z)

    def test_missing_assets_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            make_zip(args.asset_pack, {'AndroidManifest.xml': b'empty pack'})
            with zipfile.ZipFile(args.base) as b, zipfile.ZipFile(args.native_split) as n, zipfile.ZipFile(args.asset_pack) as a:
                with self.assertRaisesRegex(ValueError, 'complete install-time asset pack'):
                    apk.plan(b, n, a)

    def test_unpatched_base_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            args.base.write_bytes(args.original_base.read_bytes())
            with self.assertRaisesRegex(ValueError, 'unmodified DEX'):
                apk.assemble(args)
            self.assertFalse(args.output.exists())


if __name__ == '__main__':
    unittest.main()
