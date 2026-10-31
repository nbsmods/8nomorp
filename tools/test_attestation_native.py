#!/usr/bin/env python3
"""Local-input token integration; optionally compare with an independent JS oracle.

No proprietary libraries, expected crypto material or sample tokens are bundled.
The oracle must export computeAttestationToken and decodeAttestationToken.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
import random


def verify_records(records, expected_requests):
    if len(records) != len(expected_requests):
        raise ValueError('native output count does not match input count')
    for record, request in zip(records, expected_requests):
        if record.get('request') != request:
            raise ValueError('native output is associated with the wrong request')
        token = record.get('token', '')
        if len(token) != 160 or len(bytes.fromhex(token)) != 80:
            raise ValueError('native output is not an 80-byte token')
    seen = {}
    for record in records:
        previous = seen.setdefault(record['token'], record['request'])
        if previous != record['request']:
            raise ValueError('distinct requests returned repeated tokens')


def verify_oracle(records, reference):
    # Reference parameters are external test input, never production constants.
    script = r'''
const oracle=require(process.argv[1]);
const records=JSON.parse(require('fs').readFileSync(0,'utf8'));
let failures=0;
for (const r of records) {
 const request=Buffer.from(r.request,'hex'),token=Buffer.from(r.token,'hex');
 const decoded=oracle.decodeAttestationToken(token);
 if(r.client_time && r.client_time!==String(decoded.payloadWords[0]))throw Error('client time mismatch');
 if(r.seed8 && r.seed8!==token.subarray(0,8).toString('hex'))throw Error('seed mismatch');
 if(r.time_min && (decoded.payloadWords[0]<BigInt(r.time_min)||decoded.payloadWords[0]>BigInt(r.time_max)))throw Error('runtime clock mismatch');
 const expected=Buffer.from(oracle.computeAttestationToken(request,decoded.payloadWords[0],token.subarray(0,8)));
 if(!token.equals(expected)){console.error('Oracle mismatch for request '+r.request);failures++;}
}
if(failures)process.exit(1);
console.log('Independent oracle matches all '+records.length+' native outputs.');
'''
    subprocess.run(['node', '-e', script, str(reference.resolve())],
                   input=json.dumps(records), text=True, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path)
    parser.add_argument('--libg', type=Path)
    parser.add_argument('--shield', type=Path)
    parser.add_argument('--decoded', type=Path)
    parser.add_argument('--client-time')
    parser.add_argument('--seed')
    parser.add_argument('--records', type=Path, help='verify a previous JSONL run instead of running libraries')
    parser.add_argument('--requests', type=Path, help='requests for an existing JSONL run')
    parser.add_argument('--reference', type=Path, help='external, version-matched JS test oracle')
    parser.add_argument('--output', type=Path, help='retain integration result JSON; must be new')
    args = parser.parse_args()
    start = time.monotonic()
    if args.records:
        if not args.requests:
            parser.error('--records requires --requests')
        requests = args.requests.read_text().splitlines()
        text = args.records.read_text()
    else:
        if not all([args.base, args.libg, args.shield]):
            parser.error('provide --base, --libg, --shield')
        requests = [bytes(32).hex(), bytes(range(32)).hex(), bytes([255] * 32).hex()]
        # Exercise every low request-bit combination without assuming a codec.
        for value in range(2, 16, 2):
            request = bytearray(32)
            request[16] = value
            requests.append(request.hex())
        rng = random.Random(0)
        requests += [bytes(rng.randrange(256) for _ in range(32)).hex() for _ in range(64)]
        requests.append(requests[0])
        command = [sys.executable, str(Path(__file__).with_name('attestation.py')),
                   '--base', str(args.base), '--libg', str(args.libg), '--shield', str(args.shield)]
        if args.decoded:
            command += ['--decoded', str(args.decoded)]
        if args.client_time:
            command += ['--client-time', args.client_time]
        if args.seed:
            command += ['--seed', args.seed]
        for request in requests:
            command += ['--request', request]
        run = subprocess.run(command, check=True, stdout=subprocess.PIPE, text=True)
        text = run.stdout
    records = [json.loads(line) for line in text.splitlines()]
    verify_records(records, requests)
    for record in records:
        if args.client_time and record.get('client_time') != str(int(args.client_time)):
            raise ValueError('explicit client time was not preserved')
        if args.seed and record.get('seed8') != args.seed.lower():
            raise ValueError('explicit seed was not preserved')
    if args.reference:
        verify_oracle(records, args.reference)
    result = {'status': 'passed-oracle-comparison' if args.reference else 'passed-native-execution-only',
              'requests': len(records), 'records': records,
              'oracle_checked': bool(args.reference), 'elapsed_seconds': round(time.monotonic() - start, 2)}
    if args.output:
        with args.output.open('x') as output:
            json.dump(result, output, indent=2)
            output.write('\n')
    print('PASS: recovered-material tokens for ' + str(len(records)) + ' requests')


if __name__ == '__main__':
    main()
