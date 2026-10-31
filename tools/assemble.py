#!/usr/bin/env python3
"""Assemble matching patched base, native and install-time asset inputs.

The patched base must come from `apktool d -r`, `8nomorp all`, and `apktool b`.
Inputs are matched by package/version metadata and ZIP contents, not build hashes.
Missing install-time assets can cause a native null dereference during startup.
"""
import argparse
import copy
from contextlib import contextmanager
import hashlib
from pathlib import Path
import shutil
import struct
import zipfile

from games import SHIELDS


LIBRARY = 'lib/arm64-v8a/libg.so'


@contextmanager
def apk_zip32():
    """Use ZIP32's real 4 GiB bound, not Python's conservative 2 GiB bound.

    Android APKs must not use ZIP64. Still reject archives beyond ZIP32.
    This command-line writer is single-threaded; restore the module setting.
    """
    previous = zipfile.ZIP64_LIMIT
    zipfile.ZIP64_LIMIT = (1 << 32) - 1
    try:
        yield
    finally:
        zipfile.ZIP64_LIMIT = previous


def digest(stream):
    h = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        h.update(block)
    return h.hexdigest()


def u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def strings(data, offset):
    count, _, flags, start, _ = struct.unpack_from('<5I', data, offset + 8)
    result = []
    utf8 = flags & 0x100

    def length(pos):
        if utf8:
            n = data[pos]
            return (((n & 127) << 8) | data[pos + 1], pos + 2) if n & 128 else (n, pos + 1)
        n = u16(data, pos)
        return (((n & 32767) << 16) | u16(data, pos + 2), pos + 4) if n & 32768 else (n, pos + 2)

    for i in range(count):
        pos = offset + start + u32(data, offset + u16(data, offset + 2) + 4 * i)
        n, pos = length(pos)
        if utf8:
            n, pos = length(pos)
        result.append(data[pos:pos + n * (1 if utf8 else 2)].decode('utf-8' if utf8 else 'utf-16-le'))
    return result


def manifest_root(data):
    if len(data) < 8 or u32(data, 0) != 0x00080003 or u32(data, 4) != len(data):
        raise ValueError('invalid binary manifest')
    names = None
    pos = 8
    while pos + 8 <= len(data):
        kind, header, size = struct.unpack_from('<HHI', data, pos)
        if size < header or header < 8 or pos + size > len(data):
            raise ValueError('invalid manifest chunk')
        if kind == 1:
            names = strings(data, pos)
        elif kind == 0x102 and names is not None:
            ext = pos + header
            if names[u32(data, ext + 4)] == 'manifest':
                start, step, count = struct.unpack_from('<3H', data, ext + 8)
                if start < 20 or step != 20 or header + start + step * count > size:
                    raise ValueError('invalid manifest attributes')
                attrs = {}
                for i in range(count):
                    a = ext + start + i * step
                    name = names[u32(data, a + 4)]
                    value = u32(data, a + 16)
                    attrs[name] = names[value] if data[a + 15] == 3 else value
                return names, attrs, (pos, ext, start, step, count)
        pos += size
    raise ValueError('manifest root not found')


def standalone_manifest(data):
    names, _, (pos, ext, start, step, count) = manifest_root(data)
    result = bytearray(data)
    # Remove the attribute, not its string-pool entry or resource-map mapping.
    # Renaming it to an arbitrary string can crash binary XML readers.
    for i in range(count):
        a = ext + start + i * step
        if names[u32(data, a + 4)] != 'requiredSplitTypes':
            continue
        del result[a:a + step]
        struct.pack_into('<H', result, ext + 12, count - 1)
        for index_offset in (14, 16, 18):
            index = u16(result, ext + index_offset)
            if index:
                struct.pack_into('<H', result, ext + index_offset, 0 if index == i + 1 else index - (index > i + 1))
        struct.pack_into('<I', result, pos + 4, u32(data, pos + 4) - step)
        struct.pack_into('<I', result, 4, len(result))
        return bytes(result)
    return data


def entries(archive):
    found = {}
    for info in archive.infolist():
        if info.filename in found:
            raise ValueError('duplicate ZIP entry: ' + info.filename)
        found[info.filename] = info
    return found


def signature(name):
    return name.upper().startswith('META-INF/') and name.upper().endswith(('.SF', '.RSA', '.DSA', '.EC', '/MANIFEST.MF'))


def plan(base, native, assets):
    selected = {}
    for archive, prefix in ((base, ''), (native, 'lib/arm64-v8a/'), (assets, 'assets/')):
        for name, info in entries(archive).items():
            if not name.startswith(prefix) or signature(name):
                continue
            if name in SHIELDS:
                continue
            if name in selected:
                previous, _ = selected[name]
                with previous.open(name) as a, archive.open(name) as b:
                    if digest(a) != digest(b):
                        raise ValueError('conflicting ZIP entry: ' + name)
                continue
            selected[name] = (archive, info)
    if LIBRARY not in selected or 'assets/fingerprint.json' not in selected:
        raise ValueError('native split and complete install-time asset pack are required')
    return selected


def assemble(args):
    with zipfile.ZipFile(args.original_base) as original, zipfile.ZipFile(args.base) as base, zipfile.ZipFile(args.native_split) as native, zipfile.ZipFile(args.asset_pack) as assets:
        entries(original)
        original_manifest = manifest_root(original.read('AndroidManifest.xml'))[1]
        base_manifest = manifest_root(base.read('AndroidManifest.xml'))[1]
        native_manifest = manifest_root(native.read('AndroidManifest.xml'))[1]
        if (not original_manifest.get('package') or
                original_manifest.get('package') != base_manifest.get('package') or
                original_manifest.get('versionCode') != base_manifest.get('versionCode') or
                original_manifest.get('package') != native_manifest.get('package') or
                original_manifest.get('versionCode') != native_manifest.get('versionCode')):
            raise ValueError('base/native split package or version metadata mismatch')
        dex_changed = False
        for name in original.namelist():
            if name.startswith('classes') and name.endswith('.dex'):
                with original.open(name) as a, base.open(name) as b:
                    dex_changed |= digest(a) != digest(b)
        if not dex_changed:
            raise ValueError('unmodified DEX: run 8nomorp all on the decoded base first')
        # apktool -r must preserve compiled resources and original assets.
        for name in original.namelist():
            if name == 'resources.arsc' or name.startswith(('assets/', 'res/')):
                with original.open(name) as a, base.open(name) as b:
                    if digest(a) != digest(b):
                        raise ValueError('patched base changed original resources: ' + name)
        selected = plan(base, native, assets)
        # Apktool drops META-INF by default. ServiceLoader descriptors are
        # runtime inputs (not signing metadata), notably Kotlin's dispatcher.
        for name, info in entries(original).items():
            if name.startswith('META-INF/') and not signature(name):
                selected[name] = (original, info)
        replacements = {LIBRARY: Path(args.library)}
        for value in getattr(args, 'extra_library', []):
            name, separator, path = value.partition('=')
            key = 'lib/arm64-v8a/' + name
            if not separator or Path(name).name != name or not name.endswith('.so') or key not in selected or key in replacements:
                raise ValueError('invalid or duplicate native replacement: ' + name)
            replacements[key] = Path(path)
        additions = {}
        for value in getattr(args, 'add_library', []):
            name, separator, path = value.partition('=')
            key = 'lib/arm64-v8a/' + name
            if (not separator or Path(name).name != name or not name.startswith('lib') or
                    not name.endswith('.so') or key in selected or key in additions or key in SHIELDS):
                raise ValueError('invalid or duplicate native addition: ' + name)
            additions[key] = Path(path)
        manifest = standalone_manifest(base.read('AndroidManifest.xml'))
        output = Path(args.output)
        # Refuse existing output, including symlinks. Only delete our own partial output.
        stream = output.open('xb')
        try:
            with apk_zip32(), stream, zipfile.ZipFile(stream, 'w', allowZip64=False) as out:
                for name, (archive, info) in selected.items():
                    info = copy.copy(info)
                    if name == 'resources.arsc':
                        info.compress_type = zipfile.ZIP_STORED
                    if name == 'AndroidManifest.xml':
                        out.writestr(info, manifest)
                    elif name in replacements:
                        with replacements[name].open('rb') as source, out.open(info, 'w') as dest:
                            shutil.copyfileobj(source, dest, 1024 * 1024)
                    else:
                        with archive.open(name) as source, out.open(info, 'w') as dest:
                            shutil.copyfileobj(source, dest, 1024 * 1024)
                for name, path in additions.items():
                    out.write(path, name, compress_type=zipfile.ZIP_STORED)
        except BaseException:
            output.unlink()
            raise
    print('Assembled matching APK inputs; zipalign and sign before installing.')
    print('Assembly does not validate startup, gameplay or server compatibility.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('original-base', 'base', 'native-split', 'asset-pack', 'library', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--extra-library', action='append', default=[], metavar='NAME=PATH')
    parser.add_argument('--add-library', action='append', default=[], metavar='NAME=PATH')
    args = parser.parse_args()
    try:
        assemble(args)
    except (OSError, ValueError, KeyError, IndexError, struct.error, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        parser.exit(1, 'error: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()
