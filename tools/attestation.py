#!/usr/bin/env python3
"""Generate tokens using SHA states and codec material recovered from matching libraries."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from sparse_strings import CONST

OWNER = r'[A-Za-z0-9_$/]+'


def method_body(source, signature):
    bodies = re.findall(r'^\.method[^\n]*\s' + re.escape(signature) +
                        r'\s*\n(.*?)^\.end method\s*$', source, re.M | re.S)
    if len(bodies) != 1:
        raise ValueError('expected one method: ' + signature)
    return bodies[0]


def registration_for(source, owner):
    body = method_body(source, '<clinit>()V')
    classes, integers, found = {}, {}, []
    for line in body.splitlines():
        match = re.match(r'\s*const-class\s+([vp]\d+),\s*L(' + OWNER + r');\s*(?:#.*)?$', line)
        if match:
            classes[match[1]] = match[2]
            integers.pop(match[1], None)
            continue
        match = CONST.match(line)
        if match:
            integers[match[1]] = int(match[2], 0)
            classes.pop(match[1], None)
            continue
        call = re.match(r'\s*invoke-static\s+\{([vp]\d+),\s*([vp]\d+)\},\s*L' + OWNER +
                        r';->\w+\(Ljava/lang/Class;I\)V\s*(?:#.*)?$', line)
        if call and classes.get(call[1]) == owner and call[2] in integers:
            value = integers[call[2]]
            if not 0 <= value <= 0xffffffff:
                raise ValueError('registration ID is not uint32')
            found.append(value)
        # Never reuse a stale literal after arithmetic or another register write.
        write = re.match(r'\s*(?!invoke-|if-|return-|sput-|iput-|aput-|monitor-|throw\b)'
                         r'[a-z][\w/-]*\s+([vp]\d+)\b', line)
        if write:
            classes.pop(write[1], None)
            integers.pop(write[1], None)
    if len(found) != 1:
        raise ValueError('expected one attestation class registration')
    return found[0]


def discover_entry(decoded):
    wrappers = list(decoded.glob('smali*/com/supercell/titan/PromonTitan.smali'))
    if len(wrappers) != 1:
        raise ValueError('expected one original PromonTitan wrapper')
    body = method_body(wrappers[0].read_text(), 'getAppAttestationResposeToken([B)[B')
    calls = re.findall(r'invoke-virtual\s+\{[^}]*\},\s*L(' + OWNER +
                       r');->(\w+)\(\[B\)\[B', body)
    if len(calls) != 1:
        raise ValueError('unsupported attestation wrapper layout')
    owner, name = calls[0]
    paths = list(decoded.glob('smali*/' + owner + '.smali'))
    if len(paths) != 1:
        raise ValueError('missing/ambiguous original attestation class')
    source = paths[0].read_text()
    native = re.findall(r'^\.method[^\n]*\bnative\s+' + re.escape(name) +
                        r'\(\[B\)\[B\s*$', source, re.M)
    if len(native) != 1:
        raise ValueError('attestation class is not the original native implementation')
    return owner, registration_for(source, owner)


def request_hex(text):
    if not re.fullmatch(r'[0-9a-fA-F]{64}', text):
        raise ValueError('each request must be exactly 32 bytes of hexadecimal')
    return text.lower()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--libg', type=Path, required=True)
    parser.add_argument('--shield', type=Path, required=True)
    parser.add_argument('--decoded', type=Path, help='already decoded, ORIGINAL base APK')
    parser.add_argument('--request', action='append', default=[], help='32 bytes of hex; repeat to batch')
    parser.add_argument('--client-time', default=os.environ.get('PEPPER_ATTEST_CLIENT_TIME') or 'auto', help='uint64 seconds; default: now')
    seeds = parser.add_mutually_exclusive_group()
    seeds.add_argument('--seed', help='8 bytes of hexadecimal; default: deterministic')
    seeds.add_argument('--random-seed', action='store_true', help='use OS entropy for each seed')
    parser.add_argument('--requests', type=Path, help='file containing one request hex per line')
    parser.add_argument('--binary', type=Path, default=Path(__file__).resolve().parents[1] / '8nomorp')
    parser.add_argument('--apktool', default='apktool')
    parser.add_argument('--workdir', type=Path, default=Path.cwd(), help='parent for temporary files')
    args = parser.parse_args(argv)
    if args.client_time != 'auto' and (not re.fullmatch(r'[0-9]+', args.client_time) or int(args.client_time) > 2**64-1):
        parser.error('--client-time must be uint64 seconds')
    if args.seed is not None and not re.fullmatch(r'[0-9a-fA-F]{16}', args.seed):
        parser.error('--seed must be exactly 8 bytes of hexadecimal')
    seed = args.seed or ('random' if args.random_seed or os.environ.get('PEPPER_ATTEST_RANDOM_SEED') == '1' else 'deterministic')
    requests = args.request[:]
    if args.requests:
        requests.extend(args.requests.read_text().splitlines())
    if not requests:
        parser.error('provide --request or --requests')
    requests = [request_hex(text) for text in requests]
    if len(requests) > 65536:
        parser.error('at most 65536 requests per invocation')
    for path in [args.base, args.libg, args.shield, args.binary]:
        if not path.is_file():
            parser.error('missing input: ' + str(path))
    with tempfile.TemporaryDirectory(prefix='8nomorp-attest-', dir=args.workdir) as tmp:
        root = Path(tmp)
        decoded = args.decoded
        if decoded is None:
            decoded = root / 'decoded'
            subprocess.run([args.apktool, 'd', '-r', str(args.base), '-o', str(decoded)],
                           check=True, stdout=sys.stderr)
        owner, registration = discover_entry(decoded)
        print('Recovered attestation Java entry: ' + owner + ' registration=' + hex(registration), file=sys.stderr)
        request_file = root / 'requests.txt'
        request_file.write_text('\n'.join(requests) + '\n')
        subprocess.run([str(args.binary.resolve()), 'attest', str(args.libg.resolve()),
                        str(args.shield.resolve()), str(args.base.resolve()), owner,
                        str(registration), str(request_file.resolve()), args.client_time, seed], check=True)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print('error: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
