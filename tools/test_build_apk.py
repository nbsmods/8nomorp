#!/usr/bin/env python3
"""Exercise real package/shield discovery, without running external builders."""
import argparse
import io
import struct
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import build_apk
from games import GAMES, shield_for
from test_assemble import manifest, make_zip


def archive_bytes(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return stream.getvalue()


class ReachedPatcher(Exception):
    pass


class BuildTests(unittest.TestCase):
    def test_attestation_flags_preserve_auto_default_on_python38(self):
        for flags, expected in (([], None), (['--attestation'], True), (['--no-attestation'], False)):
            with patch('sys.argv', ['build_apk', '--base', 'base', '--native-split', 'native',
                                    '--asset-pack', 'assets', '--output', 'output', *flags]), \
                 patch.object(build_apk, 'run') as run:
                build_apk.main()
                self.assertIs(run.call_args[0][0].attestation, expected)

    def test_attestation_is_wired_before_rebuild_and_packaged_aligned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, native, asset = (root / n for n in ('base.apk', 'native.apk', 'asset.apk'))
            make_zip(base, {'AndroidManifest.xml': manifest(), 'assets/config': b'lbts-fixture'})
            make_zip(native, {shield_for('com.supercell.brawlstars'): b'shield',
                              'lib/arm64-v8a/libg.so': b'packed-game'})
            make_zip(asset, {'assets/fingerprint.json': b'{}'})
            args = argparse.Namespace(output=root / 'out.apk', xapk=None, base=base,
                native_split=native, asset_pack=asset, shield=None, dat=None, binary=root / '8nomorp',
                apktool='apktool', resource_split=[], zipalign='zipalign', keystore=None,
                attestation=True, android_cc=root / 'android-clang')
            calls = []
            def run(command, **kwargs):
                calls.append(command)
                if command[0] == 'apktool' and command[1] == 'b':
                    self.assertTrue(inject.called)
                if '--add-library' in command:
                    self.assertIn('libattestation.so=', command[-1])
                    Path(command[command.index('--output') + 1]).write_bytes(b'assembled')
                if command[0] == 'zipalign':
                    self.assertEqual(command[1:5], ['-P', '16', '-f', '4'])
                    Path(command[-1]).write_bytes(Path(command[-2]).read_bytes())
            with patch.object(build_apk, 'run_cmd', side_effect=run), \
                 patch.object(build_apk, 'recover_sparse_strings'), \
                 patch.object(build_apk.attestation_patch, 'enabled', return_value=True), \
                 patch.object(build_apk.attestation_patch, 'build', return_value=root / 'libattestation.so') as inject:
                build_apk.run(args)
            self.assertEqual(args.output.read_bytes(), b'assembled')
            self.assertEqual(inject.call_args[0][-1], args.android_cc)
            self.assertEqual(inject.call_args[0][1].name, 'libg.so')

    def test_protected_loader_requires_matching_init(self):
        data = bytearray(512)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<QQ', data, 24, 256, 64)
        struct.pack_into('<HH', data, 54, 56, 2)
        struct.pack_into('<II6Q', data, 64, 1, 5, 0, 0, 0, 512, 512, 4096)
        struct.pack_into('<II6Q', data, 120, 2, 6, 192, 192, 0, 32, 32, 8)
        struct.pack_into('<QQ', data, 192, 12, 256)
        data[256:288] = bytes.fromhex('fd7bb1a9fd030091e00701a9e20f02a9e41703a9e61f04a9e82705a9ea2f06a9')
        self.assertTrue(build_apk.protected_loader(data))
        struct.pack_into('<Q', data, 200, 260)
        self.assertFalse(build_apk.protected_loader(data))
        self.assertFalse(build_apk.protected_loader(b'not an ELF'))

    def test_xapk_and_config_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xapk = root / 'input.xapk'
            base = archive_bytes({'AndroidManifest.xml': manifest(),
                                  'assets/random-name.bin': b'lbtsfixture'})
            native = archive_bytes({'lib/arm64-v8a/libg.so': b'game',
                                    'lib/arm64-v8a/libsupercell_brawlstars.so': b'shield'})
            xapk.write_bytes(archive_bytes({'manifest.json': b'{"package_name":"com.supercell.brawlstars"}',
                                           'com.supercell.brawlstars.apk': base,
                                           'config.arm64_v8a.apk': native,
                                           'install_time_asset_pack.apk': archive_bytes({})}))
            args = argparse.Namespace(output=root / 'out.apk', xapk=xapk, base=None,
                                      native_split=None, asset_pack=None, dat=None,
                                      shield=None, apktool='apktool')

            def stop_at_build(command, env=None):
                self.assertEqual(args.dat.read_bytes(), b'lbtsfixture')
                self.assertEqual(args.shield.read_bytes(), b'shield')
                self.assertIn('-Xmx2g', env['_JAVA_OPTIONS'])
                raise RuntimeError('fixture inspected')

            with patch.object(build_apk, 'run_cmd', side_effect=stop_at_build):
                with self.assertRaisesRegex(RuntimeError, 'fixture inspected'):
                    build_apk.run(args)
            self.assertEqual(list(root.iterdir()), [xapk])

    def test_signing_password_not_logged(self):
        with patch('builtins.print') as printer, patch.object(build_apk.subprocess, 'run'):
            build_apk.run_cmd(['apksigner', '--ks-pass', 'pass:private-value'])
        self.assertNotIn('private-value', str(printer.call_args))

    def test_three_games_and_both_input_modes(self):
        for package in GAMES:
            for use_xapk in (False, True):
                with self.subTest(package=package, xapk=use_xapk), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    base, native, asset = (root / n for n in ('base.apk','native.apk','asset.apk'))
                    make_zip(base, {'AndroidManifest.xml':manifest(package=package),
                                    'assets/opaque.bin':b'lbts-config'})
                    make_zip(native, {shield_for(package):b'shield',
                                      'lib/arm64-v8a/libg.so':b'packed-game'})
                    make_zip(asset, {'assets/fingerprint.json':b'{}'})
                    xapk = root / 'input.xapk'
                    if use_xapk:
                        import json
                        with zipfile.ZipFile(xapk,'w') as z:
                            z.writestr('manifest.json',json.dumps({'package_name':package}))
                            for path,name in ((base,package+'.apk'),(native,'config.arm64_v8a.apk'),(asset,'install_time_asset_pack.apk')):
                                z.write(path,name)
                    args = argparse.Namespace(output=root/'out.apk',xapk=xapk if use_xapk else None,
                        base=base,native_split=native,asset_pack=asset,shield=None,dat=None,
                        binary=root/'8nomorp',apktool='apktool')

                    def run(command, **kwargs):
                        if command[1]=='all':
                            self.assertEqual(Path(command[2]).read_bytes(),b'lbts-config')
                            self.assertEqual(Path(command[-1]).name,Path(shield_for(package)).name)
                            self.assertEqual(Path(command[-1]).read_bytes(),b'shield')
                            raise ReachedPatcher()
                    with patch.object(build_apk,'run_cmd',side_effect=run):
                        with self.assertRaises(ReachedPatcher):
                            build_apk.run(args)
                    self.assertFalse(args.output.exists())


if __name__=='__main__':
    unittest.main()
