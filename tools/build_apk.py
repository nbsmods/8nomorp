#!/usr/bin/env python3
"""Run the complete Java + native patch and assemble one standalone APK."""
import argparse
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile


def protected_loader(data):
    """Recognize the audited ARM64 packed DT_INIT register-save wrapper."""
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
        return False
    entry, phoff = struct.unpack_from('<QQ', data, 24)
    step, count = struct.unpack_from('<HH', data, 54)
    if not entry or step < 56 or phoff + step * count > len(data):
        return False
    init, code = None, b''
    for i in range(count):
        kind, flags, offset, address, _, size, _, _ = struct.unpack_from('<II6Q', data, phoff + step * i)
        if offset + size > len(data):
            raise ValueError('invalid native ELF segment')
        if kind == 1 and flags & 1 and address <= entry < address + size:
            pos = offset + entry - address
            code = data[pos:pos + 32]
        if kind == 2:
            for pos in range(offset, offset + size - 15, 16):
                tag, value = struct.unpack_from('<QQ', data, pos)
                if tag == 0:
                    break
                if tag == 12:
                    init = value
    return init == entry and code == bytes.fromhex(
        'fd7bb1a9fd030091e00701a9e20f02a9e41703a9e61f04a9e82705a9ea2f06a9')


def run(args):
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f'output already exists: {output}')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='8nomorp-', dir=output.parent) as tmp:
        work = Path(tmp)
        decoded, patched = work / 'decoded', work / 'patched'
        patched_base = work / 'patched-base.apk'
        game = work / 'libg.so'
        native_out = work / 'native'
        dependencies = []
        unsigned = work / 'standalone-unsigned.apk'
        aligned = work / 'standalone-aligned.apk'

        if args.xapk:
            with zipfile.ZipFile(args.xapk) as archive:
                metadata = json.loads(archive.read('manifest.json'))
                package = metadata.get('package_name', '')
                if not package or '/' in package or '\\' in package:
                    raise ValueError('XAPK manifest has an invalid package_name')
                names = archive.namelist()
                for attribute, basename in (('base', package + '.apk'),
                                            ('native_split', 'config.arm64_v8a.apk'),
                                            ('asset_pack', 'install_time_asset_pack.apk')):
                    matches = [name for name in names if Path(name).name == basename]
                    if len(matches) != 1:
                        raise ValueError('XAPK must contain exactly one ' + basename)
                    path = work / basename
                    with archive.open(matches[0]) as source, path.open('xb') as dest:
                        shutil.copyfileobj(source, dest, 1024 * 1024)
                    setattr(args, attribute, path)
        if not args.dat:
            with zipfile.ZipFile(args.base) as archive:
                candidates = []
                for info in archive.infolist():
                    if info.filename.startswith('assets/') and not info.is_dir():
                        with archive.open(info) as stream:
                            if stream.read(4) == b'lbts':
                                candidates.append(info.filename)
                if len(candidates) != 1:
                    raise ValueError('expected exactly one LBTS asset; provide --dat explicitly')
                args.dat = work / 'config.dat'
                args.dat.write_bytes(archive.read(candidates[0]))

        with zipfile.ZipFile(args.native_split) as split:
            if not args.shield:
                args.shield = work / 'libsupercell_brawlstars.so'
                args.shield.write_bytes(split.read('lib/arm64-v8a/libsupercell_brawlstars.so'))
            candidates = [n for n in split.namelist()
                          if n == 'lib/arm64-v8a/libg.so']
            if len(candidates) != 1:
                raise ValueError('native split must contain exactly one ARM64 libg.so')
            with split.open(candidates[0]) as src, game.open('wb') as dst:
                shutil.copyfileobj(src, dst)
            for name in split.namelist():
                if not name.startswith('lib/arm64-v8a/') or not name.endswith('.so') or name == candidates[0]:
                    continue
                data = split.read(name)
                if protected_loader(data):
                    path = work / Path(name).name
                    path.write_bytes(data)
                    dependencies.append(path)

        apktool_env = os.environ.copy()
        apktool_env['_JAVA_OPTIONS'] = (apktool_env.get('_JAVA_OPTIONS', '') +
                                       ' -Xmx' + os.environ.get('APKTOOL_HEAP', '2g')).strip()
        run_cmd([args.apktool, 'd', '-r', str(args.base), '-o', str(decoded)], env=apktool_env)
        binary = args.binary.resolve()
        run_cmd([str(binary), 'all', str(args.dat), str(decoded), str(patched),
                 '--so', str(args.shield)])
        run_cmd([args.apktool, 'b', str(patched), '-o', str(patched_base)], env=apktool_env)
        run_cmd([str(binary), 'unpack', str(game), str(args.shield),
                 str(args.base), str(native_out)])
        replacements = []
        for library in dependencies:
            unpacked = work / (library.name + '-unpacked')
            print('Unpacking protected dependency:', library.name, flush=True)
            run_cmd([str(binary), 'unpack', str(library), str(args.shield), str(args.base), str(unpacked)])
            replacements.extend(['--extra-library', library.name + '=' + str(unpacked / 'libg.unpacked.so')])
        run_cmd([sys.executable, str(Path(__file__).with_name('assemble.py')),
                 '--original-base', str(args.base), '--base', str(patched_base),
                 '--native-split', str(args.native_split), '--asset-pack', str(args.asset_pack),
                 '--library', str(native_out / 'libg.unpacked.so'), '--output', str(unsigned), *replacements])
        run_cmd([args.zipalign, '-f', '4', str(unsigned), str(aligned)])
        unsigned.unlink()
        if args.keystore:
            command = [args.apksigner, 'sign', '--ks', str(args.keystore),
                       '--out', str(output), str(aligned)]
            if args.ks_pass:
                command[4:4] = ['--ks-pass', args.ks_pass]
            run_cmd(command)
        else:
            shutil.copyfile(aligned, output)
        aligned.unlink()
        print(f'Complete patched APK written to {output}')
        if not args.keystore:
            print('APK is aligned but unsigned; provide --keystore to sign it.')
        print('Java protections and verified native resolver calls were patched. '
              'This does not establish launch, login, gameplay, or mod compatibility.')


def run_cmd(command, env=None):
    shown = list(map(str, command))
    if '--ks-pass' in shown:
        shown[shown.index('--ks-pass') + 1] = '[redacted]'
    print('+', ' '.join(shown), flush=True)
    subprocess.run(command, check=True, env=env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path(__file__).resolve().parents[1] / '8nomorp')
    parser.add_argument('--xapk', type=Path, help='matching base, ARM64 split and install-time assets in one archive')
    parser.add_argument('--base', type=Path)
    parser.add_argument('--shield', type=Path, help='default: extract the shield from the native split')
    parser.add_argument('--dat', type=Path, help='default: discover the single LBTS asset in the base APK')
    parser.add_argument('--native-split', type=Path)
    parser.add_argument('--asset-pack', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--keystore', type=Path)
    parser.add_argument('--ks-pass', help='apksigner keystore password argument, e.g. env:KS_PASS')
    parser.add_argument('--apktool', default='apktool')
    parser.add_argument('--zipalign', default='zipalign')
    parser.add_argument('--apksigner', default='apksigner')
    args = parser.parse_args()
    if args.xapk and any((args.base, args.native_split, args.asset_pack)):
        parser.error('use --xapk OR --base/--native-split/--asset-pack, not both')
    if not args.xapk and not all((args.base, args.native_split, args.asset_pack)):
        parser.error('provide --xapk or all of --base, --native-split and --asset-pack')
    try:
        run(args)
    except subprocess.CalledProcessError as exc:
        parser.exit(1, f'error: {Path(exc.cmd[0]).name} exited with status {exc.returncode}\n')
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        parser.exit(1, f'error: {exc}\n')


if __name__ == '__main__':
    main()
