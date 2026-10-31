#!/usr/bin/env python3
"""Fresh v66.300 integration test with local inputs, not a runtime certification.

No predecoded tree, cached context, downloaded file, or manual patch is used.
The output directory must not exist; logs and artifacts are retained on failure.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile


# Fixture identities are regression-test expectations, NOT production acceptance
# rules. The real all command still discovers/authenticates the matching context.
FIXTURE_HASHES = {
    'base': 'e83f492fbbff0bad3f5f9194f6c43e8850bde09642421576245b0ce34cd182a9',
    'shield': 'e41b55cf53943eb458c63d4191e724f4b7a1bd4172dbb1c8114c29c169b57d23',
    'dat': '133ab440410c096eabf04e867342fe70c8762eaa09a5286cec6e4a2bc67dc94f',
}


def digest(stream):
    h = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        h.update(block)
    return h.hexdigest()


def validate_inputs(paths):
    for name, expected in FIXTURE_HASHES.items():
        with paths[name].open('rb') as stream:
            if digest(stream) != expected:
                raise ValueError('not the v66.300 regression fixture: ' + name)


def context_captures(log, root):
    candidates = re.findall(r'^\[\+\] context candidate: (.*?) \(entry ', log, re.MULTILINE)
    if not candidates:
        raise ValueError('no freshly generated contexts')
    if any(root / 'tmp' not in Path(candidate).parents for candidate in candidates):
        raise ValueError('context was not generated inside the private test directory')
    return candidates


def run(command, root, name, env):
    with (root / (name + '.log')).open('w') as log:
        result = subprocess.run([str(x) for x in command], stdout=log,
                                stderr=subprocess.STDOUT, env=env, timeout=1800)
    if result.returncode:
        raise ValueError(name + ' failed; see ' + str(root / (name + '.log')))


def check_rebuilt(base, rebuilt):
    checked, changed = 0, 0
    with zipfile.ZipFile(base) as original, zipfile.ZipFile(rebuilt) as patched:
        dex = {name for name in original.namelist() if re.fullmatch(r'classes(?:\d+)?\.dex', name)}
        if dex != {name for name in patched.namelist() if re.fullmatch(r'classes(?:\d+)?\.dex', name)}:
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
    return checked, changed


def test(args):
    # resolve executable before changing the subprocess environment
    tool = args.tool.resolve(strict=True)
    base = args.base.resolve(strict=True)
    shield = args.shield.resolve(strict=True)
    dat = args.dat.resolve(strict=True)
    validate_inputs({'base': base, 'shield': shield, 'dat': dat})
    root = args.output.resolve()
    root.mkdir()  # exclusive; never reuse prior results
    env = os.environ.copy()
    # Keep generated context directories in this test, not another run's cache.
    (root / 'tmp').mkdir()
    env['TMPDIR'] = str(root / 'tmp')
    run([args.apktool, 'd', '-r', base, '-o', root / 'decoded'], root, 'decode', env)
    run([tool, 'all', dat, root / 'decoded', root / 'patched', '--so', shield],
        root, 'all', env)
    summary = 'Patched: 34/34 groups, 276 fields, 727 strings, 1 resolver, 84 native methods, 59 registrations, 1 protected loads, 1 crash reporters'
    if summary not in (root / 'all.log').read_text():
        raise ValueError('v66 patch coverage regression; see all.log')
    # The production command intentionally deletes its temporary contexts.
    # Check its capture log, not files that should no longer exist.
    candidates = context_captures((root / 'all.log').read_text(), root)
    run([args.apktool, 'b', root / 'patched', '-o', root / 'patched-unsigned.apk'],
        root, 'build', env)
    checked, changed_dex = check_rebuilt(base, root / 'patched-unsigned.apk')
    if changed_dex != 2:
        raise ValueError('expected both v66 DEX files to be patched')
    result = {
        'fixture': '66.300', 'status': 'offline integration passed',
        'fresh_context_candidates': len(candidates), 'changed_dex': changed_dex,
        'unchanged_resource_entries': checked,
        'runtime': 'NOT tested by this command',
        'future_versions': 'NOT certified by this command',
    }
    for name, path in [('base', base), ('shield', shield), ('dat', dat)]:
        with path.open('rb') as f:
            result[name + '_sha256'] = digest(f)
    (root / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool', type=Path, default=Path(__file__).resolve().parents[1] / '8nomorp')
    parser.add_argument('--apktool', default='apktool')
    for name in ('base', 'shield', 'dat', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        test(args)
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired, zipfile.BadZipFile) as exc:
        parser.exit(1, 'error: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()
