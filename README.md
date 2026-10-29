# 8nomorp

One native executable for authenticated LBTS decryption, Promon Java patching,
and automatic ARM64 native resolver recovery. It can also build a complete
patched APK using the included packaging scripts.

## Build

```sh
make
make test
```

Requires a C99 compiler, Make, CMake, Git, and zlib development files. The first
build fetches Unicorn 2.1.4. Use `make JOBS=4` to change dependency-build parallelism.

The APK workflow also needs Python 3, Java, Apktool, and Android SDK
`zipalign`/`apksigner` on `PATH`. Use files you are authorized to modify.

## Build an APK

From a matching XAPK containing a base APK, ARM64 split, and install-time assets:

```sh
python3 tools/build_apk.py --xapk input.xapk --output patched.apk
```

Or supply extracted inputs:

```sh
python3 tools/build_apk.py --base base.apk --native-split config.arm64_v8a.apk \
  --asset-pack install_time_asset_pack.apk --output patched.apk
```

The script discovers the LBTS asset and extracts the shield automatically.
`--dat` and `--shield` override discovery. Recognized protected native dependencies
are unpacked and verified too; the original shield is excluded from the output.
Unrecognized layouts fail rather than producing a partial native patch.

Output is aligned but unsigned by default. To sign without putting a password
in your command line or shell history:

```sh
read -rs KS_PASS; export KS_PASS
python3 tools/build_apk.py --xapk input.xapk --output patched.apk \
  --keystore release.p12 --ks-pass env:KS_PASS
unset KS_PASS
```

Output paths must be new. Temporary build files live beside the output and are
removed afterward; allow space for the extracted inputs and several APK copies.
Apktool receives a 2 GiB heap by default (`APKTOOL_HEAP=4g` overrides it).

## Main commands

```sh
./8nomorp --help
./8nomorp context shield.so contexts
./8nomorp all config.dat decoded patched --so shield.so
./8nomorp unpack library.so shield.so base.apk native-output
```

`context` recovers runtime candidates. `all` authenticates/decrypts the LBTS
config and patches the decoded Java tree. `unpack` recovers and verifies native
resolver calls. Give each action only the inputs it needs; do not reuse an
existing output directory.

Use `TMPDIR` to choose scratch storage and `CTXGEN_VERBOSE=1` for emulator logs.

## How it works

`src/ctxgen.c` emulates ARM64 shield startup with Unicorn to recover runtime
contexts and native state. `src/lbts.c` parses LBTS/protobuf envelopes and only
accepts plaintext after authentication and padding validation. `src/promon.c`
patches matched smali fields, strings, registrations, and native methods. Native
export discovers and verifies resolver call sites before writing the output.
Unsupported or ambiguous layouts fail closed; LBTS encryption is not supported.

## Scope and validation

This is not a universal Android unpacker. The offline Android/JNI fixture models
known protector behavior and still has compatibility assumptions and a small
number of audited class-specific callbacks. APK package metadata is not a promise
of support. No APKs, shield binaries, keystores, credentials, or decrypted game
assets are included. Version-specific test hashes are regression fixtures, not
runtime acceptance allowlists.

Run the Waydroid monitor with:

```sh
python3 tools/smoke_waydroid.py --package com.example.app \
  --component com.example.app/.MainActivity --duration 45 --output runtime-check
```

`tools/` contains the APK workflow and its regression tests; it is not a runtime
dependency of the core C executable. `make test-native-verifier`,
`make test-apk-assembly`, `make test-release-runner`, and
`make test-runtime-monitor` run focused checks. Release/Waydroid tests require
their own inputs and environment. Run the Python unit suite with
`python3 -m unittest discover -s tools -p 'test_*.py'`.
