"""Merge density/language resources without changing patched code or assets."""
import copy
from pathlib import Path
import shutil
import tempfile
import zipfile

from assemble import apk_zip32, digest, entries, manifest_root, signature


def validate_split(base, split):
    with zipfile.ZipFile(base) as original, zipfile.ZipFile(split) as extra:
        expected = manifest_root(original.read('AndroidManifest.xml'))[1]
        metadata = manifest_root(extra.read('AndroidManifest.xml'))[1]
        if any(metadata.get(key) != expected.get(key) for key in ('package', 'versionCode')):
            raise ValueError('resource split package/version mismatch')
        if not metadata.get('split', '').startswith('config.'):
            raise ValueError('expected a configuration resource split')
        names = entries(extra)
        if 'resources.arsc' not in names or any(
                not (name in ('AndroidManifest.xml', 'resources.arsc', 'stamp-cert-sha256') or
                     name.startswith(('res/', 'META-INF/'))) for name in names):
            raise ValueError('resource split contains unexpected non-resource entries')


def verify_payload(original, merged):
    """A resource merger must not alter executable or runtime payloads."""
    with zipfile.ZipFile(original) as before, zipfile.ZipFile(merged) as after:
        expected, actual = entries(before), entries(after)
        payload = lambda n: n.endswith('.dex') or n.startswith(('lib/', 'assets/', 'META-INF/services/'))
        if {n for n in expected if payload(n)} != {n for n in actual if payload(n)}:
            raise ValueError('resource merger changed runtime payload inventory')
        for name in expected:
            if not payload(name):
                continue
            with before.open(name) as a, after.open(name) as b:
                if digest(a) != digest(b):
                    raise ValueError('resource merger changed runtime payload: ' + name)
        a = manifest_root(before.read('AndroidManifest.xml'))[1]
        b = manifest_root(after.read('AndroidManifest.xml'))[1]
        if any(a.get(key) != b.get(key) for key in ('package', 'versionCode', 'versionName')):
            raise ValueError('resource merger changed package/version')


def merge_resources(base, splits, output, editor, run):
    if output.exists():
        raise FileExistsError(output)
    if not editor or not Path(editor).is_file():
        raise ValueError('resource splits require --apk-editor (APKEditor JAR)')
    for split in splits:
        validate_split(base, split)
    with tempfile.TemporaryDirectory(prefix='resource-splits-', dir=output.parent) as tmp:
        root = Path(tmp)
        # Stage only small resource data, not copies of the multi-GB asset pack.
        with zipfile.ZipFile(base) as source, zipfile.ZipFile(root/'base.apk', 'w') as dest:
            for name in source.namelist():
                if name in ('AndroidManifest.xml', 'resources.arsc') or name.startswith('res/'):
                    dest.writestr(name, source.read(name))
        for index, split in enumerate(splits):
            shutil.copyfile(split, root/f'config-{index}.apk')
        merged = root/'merged.zip'
        run(['java', '-Xmx2g', '-jar', str(editor), 'm', '-i', str(root),
             '-o', str(merged), '-validate-modules'])
        # Preserve our manifest, DEX, assets, native libraries and metadata.
        # Only the resource table and its referenced files come from the merger.
        with zipfile.ZipFile(base) as source, zipfile.ZipFile(merged) as resources:
            with apk_zip32(), zipfile.ZipFile(output, 'x', allowZip64=False) as dest:
                for info in source.infolist():
                    if info.filename == 'resources.arsc' or info.filename.startswith('res/') or signature(info.filename):
                        continue
                    with source.open(info) as src, dest.open(info, 'w') as dst:
                        shutil.copyfileobj(src, dst, 1024 * 1024)
                for info in resources.infolist():
                    if info.filename == 'resources.arsc' or info.filename.startswith('res/'):
                        data = resources.read(info.filename)
                        info = copy.copy(info)
                        if info.filename == 'resources.arsc':
                            info.compress_type = zipfile.ZIP_STORED
                        dest.writestr(info, data)
        verify_payload(base, output)
