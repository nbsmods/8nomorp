#!/usr/bin/env python3
"""Fresh, version-independent Java patch/rebuild test; not runtime certification."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

from test_v66_release import context_captures, digest, run


def coverage(log):
    matches = re.findall(r'^Patched: (\d+)/(\d+) groups, (\d+) fields, (\d+) strings,',
                         log, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError('expected one patch coverage summary')
    matched, total, fields, strings = map(int, matches[0])
    if not total or matched != total or not fields or not strings:
        raise ValueError('incomplete patch coverage')
    return {'groups': total, 'fields': fields, 'strings': strings}


def extract_config(base, root):
    with zipfile.ZipFile(base) as archive:
        candidates = []
        for info in archive.infolist():
            if info.filename.startswith('assets/') and not info.is_dir():
                with archive.open(info) as stream:
                    if stream.read(4) == b'lbts':
                        candidates.append(info)
        if len(candidates) != 1:
            raise ValueError('expected exactly one LBTS asset')
        path = root / 'config.dat'
        path.write_bytes(archive.read(candidates[0]))
        return path


def test(args):
    tool, base, shield = (p.resolve(strict=True) for p in (args.tool, args.base, args.shield))
    root = args.output.resolve()
    root.mkdir()
    env = os.environ.copy()
    (root / 'tmp').mkdir()
    env['TMPDIR'] = str(root / 'tmp')
    dat = extract_config(base, root)
    result = {'status': 'running', 'runtime': 'NOT tested', 'native_export': 'NOT tested'}
    try:
        run([args.apktool, 'd', '-r', base, '-o', root / 'decoded'], root, 'decode', env)
        run([tool, 'all', dat, root / 'decoded', root / 'patched', '--so', shield],
            root, 'all', env)
        log = (root / 'all.log').read_text()
        result.update(coverage(log))
        result['fresh_context_candidates'] = len(context_captures(log, root))
        run([args.apktool, 'b', root / 'patched', '-o', root / 'patched-unsigned.apk'],
            root, 'build', env)
        checked, changed = 0, 0
        with zipfile.ZipFile(base) as original, zipfile.ZipFile(root / 'patched-unsigned.apk') as patched:
            dex = {n for n in original.namelist() if re.fullmatch(r'classes(?:\d+)?\.dex', n)}
            if dex != {n for n in patched.namelist() if re.fullmatch(r'classes(?:\d+)?\.dex', n)}:
                raise ValueError('DEX entry set changed')
            for name in original.namelist():
                if name == 'resources.arsc' or name.startswith(('res/', 'assets/')):
                    with original.open(name) as a, patched.open(name) as b:
                        if digest(a) != digest(b):
                            raise ValueError('resource changed: ' + name)
                    checked += 1
                elif name in dex:
                    a, b = original.read(name), patched.read(name)
                    if not b.startswith(b'dex\n'):
                        raise ValueError('invalid rebuilt DEX: ' + name)
                    changed += a != b
            if not changed:
                raise ValueError('no DEX changes')
        result.update(status='offline Java integration passed', changed_dex=changed,
                      unchanged_resource_entries=checked)
    except Exception as exc:
        result.update(status='FAILED', error=str(exc))
        raise
    finally:
        for name, path in [('base', base), ('shield', shield), ('dat', dat)]:
            with path.open('rb') as stream:
                result[name + '_sha256'] = digest(stream)  # provenance only, never acceptance
        (root / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool', type=Path, default=Path(__file__).resolve().parents[1] / '8nomorp')
    parser.add_argument('--apktool', default='apktool')
    for name in ('base', 'shield', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        test(args)
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired, zipfile.BadZipFile) as exc:
        parser.exit(1, 'error: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()
