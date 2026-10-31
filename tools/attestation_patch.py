"""Build and wire a per-build ARM64 attestation bridge; unknown recipes fail closed."""
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess

from attestation import discover_entry, method_body

BRIDGE = 'com/supercell/titan/AttestationBridge'
SIGNATURE = 'getAppAttestationResposeToken([B)[B'
# Only this recipe has independent oracle coverage. This is not a key allowlist.
VALIDATED = {('com.supercell.brawlstars', '69.414')}


def enabled(metadata, requested):
    supported = (metadata.get('package'), metadata.get('versionName')) in VALIDATED
    if requested and not supported:
        raise ValueError('attestation recipe is not validated for this package/version')
    return supported if requested is None else requested


def material_header(material):
    states = []
    for name in ('primary', 'secondary'):
        value = material.get(name)
        if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', value):
            raise ValueError('invalid recovered SHA state: ' + name)
        states.append('{' + ','.join('0x' + value[i:i+2] for i in range(0, 64, 2)) + '}')
    value = material.get('multiplier')
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]+', value) or not 0 < int(value) < 2**64:
        raise ValueError('invalid recovered attestation multiplier')
    return ('static const attestation_material build_material = {' + ','.join(states) +
            ',UINT64_C(' + str(int(value)) + ')};\n')


def compiler(explicit=None):
    if explicit or os.environ.get('ANDROID_CC'):
        return str(explicit or os.environ['ANDROID_CC'])
    ndk = os.environ.get('ANDROID_NDK_HOME') or os.environ.get('ANDROID_NDK_ROOT')
    if ndk:
        for path in sorted(Path(ndk).glob('toolchains/llvm/prebuilt/*/bin/aarch64-linux-android29-clang')):
            if os.access(path, os.X_OK):
                return str(path)
    found = shutil.which('aarch64-linux-android29-clang')
    if not found:
        raise ValueError('attestation requires an Android NDK compiler: set ANDROID_NDK_HOME or --android-cc')
    return found


def patch_wrapper(patched):
    paths = list(patched.glob('smali*/com/supercell/titan/PromonTitan.smali'))
    if len(paths) != 1:
        raise ValueError('missing/ambiguous patched PromonTitan wrapper')
    path = paths[0]
    source = path.read_text()
    method_body(source, SIGNATURE)  # Refuse missing or ambiguous entrypoints.
    pattern = r'^\.method[^\n]*\s' + re.escape(SIGNATURE) + r'\s*\n.*?^\.end method\s*$'
    replacement = ('.method public static ' + SIGNATURE + '\n'
                   '    .locals 1\n'
                   '    invoke-static {p0}, L' + BRIDGE + ';->compute([B)[B\n'
                   '    move-result-object v0\n    return-object v0\n.end method\n')
    target = path.parents[3] / (BRIDGE + '.smali')
    if target.exists() or list(patched.glob('smali*/' + BRIDGE + '.smali')):
        raise ValueError('attestation bridge already exists')
    target.write_text('.class public final L' + BRIDGE + ';\n.super Ljava/lang/Object;\n\n'
                      '.method static constructor <clinit>()V\n    .locals 1\n'
                      '    const-string v0, "attestation"\n'
                      '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
                      '    return-void\n.end method\n\n'
                      '.method public static native compute([B)[B\n.end method\n')
    path.write_text(re.sub(pattern, lambda _: replacement, source, flags=re.M | re.S))


def compile_library(material, work, run_cmd, android_cc=None):
    cc = compiler(android_cc)
    header = work / 'attestation_material.h'
    header.write_text(material_header(material))
    src = Path(__file__).resolve().parents[1] / 'src'
    output = work / 'libattestation.so'
    run_cmd([cc, '-std=c99', '-D_GNU_SOURCE', '-O2', '-shared', '-fPIC', '-fvisibility=hidden',
             '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections', '-Wl,-z,defs',
             '-Wl,-z,max-page-size=16384', '-Wl,-soname,libattestation.so',
             '-I' + str(src), '-I' + str(work), str(src / 'attestation_jni.c'),
             str(src / 'attestation.c'), str(src / 'lbts.c'), '-lm', '-o', str(output)])
    data = output.read_bytes()
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<HH', data, 16) != (3, 183):
        raise ValueError('attestation compiler did not produce an ARM64 shared library')
    return output


def build(binary, game, shield, base, decoded, patched, work, run_cmd, android_cc=None):
    cc = compiler(android_cc)  # Check the toolchain before expensive emulation.
    owner, registration = discover_entry(decoded)
    result = subprocess.run([str(binary), 'attest-material', str(game), str(shield), str(base),
                             owner, str(registration)], check=True, stdout=subprocess.PIPE, text=True)
    output = compile_library(json.loads(result.stdout), work, run_cmd, cc)
    patch_wrapper(patched)
    print('Wired library-derived attestation through PromonTitan; server acceptance is unverified.', flush=True)
    return output
