#!/usr/bin/env python3
"""Run the complete Java + native patch and assemble one standalone APK."""
import argparse
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

from assemble import manifest_root
from games import ABIS, select_abi, shield_for
from apk_bundle import extract_bundle
from sparse_strings import recover as recover_sparse_strings
from resource_splits import merge_resources
import attestation_patch


def protected_loader(data):
    """Recognize audited ARM packed DT_INIT register-save wrappers."""
    if len(data) < 52 or data[:4] != b'\x7fELF' or data[5] != 1 or data[4] not in (1, 2):
        return False
    arm32 = data[4] == 1
    if not arm32 and len(data) < 64:
        return False
    pair = '<II' if arm32 else '<QQ'
    entry, phoff = struct.unpack_from(pair, data, 24)
    step, count = struct.unpack_from('<HH', data, 42 if arm32 else 54)
    if not entry or step < (32 if arm32 else 56) or phoff + step * count > len(data):
        return False
    init, code = None, b''
    tag_size = struct.calcsize(pair)
    for i in range(count):
        fields = struct.unpack_from('<8I' if arm32 else '<II6Q', data, phoff + step * i)
        if arm32:
            kind, offset, address, _, size, _, flags, _ = fields
        else:
            kind, flags, offset, address, _, size, _, _ = fields
        if offset + size > len(data):
            raise ValueError('invalid native ELF segment')
        if kind == 1 and flags & 1 and address <= entry < address + size:
            pos = offset + entry - address
            code = data[pos:pos + (20 if arm32 else 32)]
        if kind == 2:
            for pos in range(offset, offset + size - tag_size + 1, tag_size):
                tag, value = struct.unpack_from(pair, data, pos)
                if tag == 0:
                    break
                if tag == 12:
                    init = value
    if init != entry:
        return False
    if arm32:
        return (len(code) == 20 and code[:8] == bytes.fromhex('04e02de5ff1f2de9') and
                code[11] == 0xeb and code[12:] == bytes.fromhex('ff1fbde804f09de4'))
    return code == bytes.fromhex(
        'fd7bb1a9fd030091e00701a9e20f02a9e41703a9e61f04a9e82705a9ea2f06a9')


def run(args):
    abi = getattr(args, 'abi', None)
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

        bundle = getattr(args, 'apkm', None) or args.xapk
        if bundle:
            inputs = extract_bundle(bundle, work, abi)
            abi = inputs['abi']
            for attribute in ('base', 'native_split', 'asset_pack'):
                setattr(args, attribute, inputs[attribute])
            args.resource_split = list(getattr(args, 'resource_split', [])) + inputs['resource_split']
        else:
            with zipfile.ZipFile(args.native_split) as split:
                abi = select_abi({a for a in ABIS if 'lib/' + a + '/libg.so' in split.namelist()}, abi)
        with zipfile.ZipFile(args.base) as archive:
            metadata = manifest_root(archive.read('AndroidManifest.xml'))[1]
            package = metadata.get('package')
        shield_name = shield_for(package, abi)
        if abi != 'arm64-v8a' and getattr(args, 'attestation', None):
            raise ValueError('attestation bridge currently requires arm64-v8a')
        attest = abi == 'arm64-v8a' and attestation_patch.enabled(metadata, getattr(args, 'attestation', None))
        if attest:
            attestation_patch.compiler(getattr(args, 'android_cc', None))
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
                args.shield = work / Path(shield_name).name
                args.shield.write_bytes(split.read(shield_name))
            candidates = [n for n in split.namelist()
                          if n == 'lib/' + abi + '/libg.so']
            if len(candidates) != 1:
                raise ValueError('native split must contain exactly one ' + abi + ' libg.so')
            with split.open(candidates[0]) as src, game.open('wb') as dst:
                shutil.copyfileobj(src, dst)
            for name in split.namelist():
                if not name.startswith('lib/' + abi + '/') or not name.endswith('.so') or name in (candidates[0], shield_name):
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
                 '--apk', str(args.base), '--so', str(args.shield)])
        recover_sparse_strings(binary, args.shield, args.base, decoded, patched, work, run_cmd)
        replacements = []
        if attest:
            bridge = attestation_patch.build(binary, game, args.shield, args.base, decoded, patched,
                                             work, run_cmd, getattr(args, 'android_cc', None))
            replacements += ['--add-library', 'libattestation.so=' + str(bridge)]
        run_cmd([args.apktool, 'b', str(patched), '-o', str(patched_base)], env=apktool_env)
        run_cmd([str(binary), 'unpack', str(game), str(args.shield),
                 str(args.base), str(native_out)])
        for library in dependencies:
            unpacked = work / (library.name + '-unpacked')
            print('Unpacking protected dependency:', library.name, flush=True)
            run_cmd([str(binary), 'unpack', str(library), str(args.shield), str(args.base), str(unpacked)])
            replacements.extend(['--extra-library', library.name + '=' + str(unpacked / 'libg.unpacked.so')])
        run_cmd([sys.executable, str(Path(__file__).with_name('assemble.py')),
                 '--original-base', str(args.base), '--base', str(patched_base),
                 '--native-split', str(args.native_split), '--asset-pack', str(args.asset_pack),
                 '--abi', abi,
                 '--library', str(native_out / 'libg.unpacked.so'), '--output', str(unsigned), *replacements])
        if getattr(args, 'resource_split', None):
            merged = work / 'resources-complete.apk'
            merge_resources(unsigned, args.resource_split, merged, args.apk_editor, run_cmd)
            unsigned.unlink()
            merged.rename(unsigned)
        run_cmd([args.zipalign, *(['-P', '16'] if attest else []), '-f', '4', str(unsigned), str(aligned)])
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
    bundle = parser.add_mutually_exclusive_group()
    bundle.add_argument('--xapk', type=Path, help='matching base, native split and install-time assets in one archive')
    bundle.add_argument('--apkm', type=Path, help='APKMirror bundle containing matching APK splits')
    parser.add_argument('--abi', choices=ABIS, help='default: detect from inputs, prefer ARM64 when both are present')
    parser.add_argument('--base', type=Path)
    parser.add_argument('--shield', type=Path, help='default: extract the shield from the native split')
    parser.add_argument('--dat', type=Path, help='default: discover the single LBTS asset in the base APK')
    parser.add_argument('--native-split', type=Path)
    parser.add_argument('--asset-pack', type=Path)
    parser.add_argument('--resource-split', type=Path, action='append', default=[],
                        help='matching density/language configuration APK; repeatable')
    parser.add_argument('--apk-editor', type=Path,
                        help='APKEditor JAR required when merging resource splits')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--keystore', type=Path)
    parser.add_argument('--ks-pass', help='apksigner keystore password argument, e.g. env:KS_PASS')
    parser.add_argument('--apktool', default='apktool')
    parser.add_argument('--zipalign', default='zipalign')
    parser.add_argument('--apksigner', default='apksigner')
    attestation = parser.add_mutually_exclusive_group()
    attestation.add_argument('--attestation', action='store_true', default=None,
                             help='add library-derived libattestation.so; automatic for validated Brawl Stars 69.414')
    attestation.add_argument('--no-attestation', dest='attestation', action='store_false',
                             help='keep the existing attestation implementation')
    parser.add_argument('--android-cc', type=Path, help='ARM64 Android NDK compiler (or set ANDROID_NDK_HOME)')
    args = parser.parse_args()
    if (args.xapk or args.apkm) and any((args.base, args.native_split, args.asset_pack)):
        parser.error('use a bundle OR --base/--native-split/--asset-pack, not both')
    if not (args.xapk or args.apkm) and not all((args.base, args.native_split, args.asset_pack)):
        parser.error('provide --xapk/--apkm or all of --base, --native-split and --asset-pack')
    try:
        run(args)
    except subprocess.CalledProcessError as exc:
        parser.exit(1, f'error: {Path(exc.cmd[0]).name} exited with status {exc.returncode}\n')
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        parser.exit(1, f'error: {exc}\n')


if __name__ == '__main__':
    main()
