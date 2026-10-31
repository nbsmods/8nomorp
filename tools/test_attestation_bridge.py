#!/usr/bin/env python3
"""Execute the patched APK's real Java -> Android JNI path against an external oracle.

Uses adb/dalvikvm, without installing the APK, touching game data or contacting servers.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from test_attestation_native import verify_oracle, verify_records

HARNESS = r'''
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.*;
public class AttestationHarness {
  static Method method;
  static String hex(byte[] b) {
    StringBuilder s=new StringBuilder();
    for(byte v:b)s.append(String.format("%02x",v&255));
    return s.toString();
  }
  static String compute(byte[] request) throws Exception {
    long before=System.currentTimeMillis()/1000;
    byte[] result=(byte[])method.invoke(null,(Object)request);
    long after=System.currentTimeMillis()/1000;
    if(result==null||result.length!=80)throw new AssertionError("bad result length");
    return "{\"request\":\""+hex(request)+"\",\"token\":\""+hex(result)+
      "\",\"time_min\":\""+before+"\",\"time_max\":\""+after+"\"}";
  }
  public static void main(String[] args) throws Exception {
    method=Class.forName("com.supercell.titan.PromonTitan")
      .getMethod("getAppAttestationResposeToken",byte[].class);
    for(byte[] bad:new byte[][]{null,new byte[0],new byte[31],new byte[33]}) {
      try { method.invoke(null,(Object)bad);throw new AssertionError("invalid input accepted"); }
      catch(InvocationTargetException e) {
        if(!(e.getCause() instanceof IllegalArgumentException))throw e;
      }
    }
    ExecutorService pool=Executors.newFixedThreadPool(8);
    try {
      List<Future<String>> results=new ArrayList<>();Random rng=new Random(0);
      for(int i=0;i<128;i++) {
        final byte[] request=new byte[32];
        if(i<16)request[16]=(byte)i;else rng.nextBytes(request);
        results.add(pool.submit(()->compute(request)));
      }
      for(Future<String> result:results)System.out.println(result.get());
    } finally { pool.shutdownNow(); }
  }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True, help='rebuilt APK containing patched PromonTitan and bridge')
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True, help='version-matched JS oracle')
    parser.add_argument('--d8', required=True)
    parser.add_argument('--serial')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output already exists')
    adb = ['adb'] + (['-s', args.serial] if args.serial else [])
    def run(command, **kwargs):
        return subprocess.run(command, check=True, text=True, stdout=subprocess.PIPE, **kwargs).stdout
    with tempfile.TemporaryDirectory(prefix='attestation-bridge-', dir=args.output.resolve().parent) as tmp:
        root = Path(tmp)
        source = root / 'AttestationHarness.java'
        source.write_text(HARNESS)
        run(['javac', '--release', '8', str(source)])
        run([args.d8, '--min-api', '29', '--output', str(root), str(root / 'AttestationHarness.class')])
        remote = run(adb + ['shell', 'mktemp', '-d', '/data/local/tmp/attestation-XXXXXXXX']).strip()
        if not remote.startswith('/data/local/tmp/attestation-') or '/' in remote[len('/data/local/tmp/'):]:
            raise ValueError('unexpected device temporary path')
        paths = [remote + '/' + name for name in ('base.apk', 'classes.dex', 'libattestation.so')]
        try:
            for source, target in zip((args.apk, root / 'classes.dex', args.library), paths):
                run(adb + ['push', str(source), target])
            text = run(adb + ['shell', 'env', 'CLASSPATH=' + ':'.join(paths[:2]),
                             'dalvikvm', '-Djava.library.path=' + remote, 'AttestationHarness'])
            records = [json.loads(line) for line in text.splitlines() if line.startswith('{')]
            if len(records) != 128:
                raise ValueError('incomplete Android JNI execution')
            verify_records(records, [record['request'] for record in records])
            if len({record['token'][:16] for record in records}) != len(records):
                raise ValueError('runtime repeated a random seed')
            verify_oracle(records, args.reference)
            with args.output.open('x') as output:
                json.dump({'status': 'passed-android-java-jni-oracle', 'records': records,
                           'server_acceptance_verified': False}, output, indent=2)
            print('PASS: APK Java wrapper, JNI, clock, entropy, invalid inputs and 128 concurrent oracle comparisons')
        finally:
            run(adb + ['shell', 'rm', '-f', *paths])
            run(adb + ['shell', 'rmdir', remote])


if __name__ == '__main__':
    main()
