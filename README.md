# 8nomorp

Native LBTS decryption, Promon Java patching, and native resolver recovery.

## Build

```sh
make
make check
```

Requires a C99 compiler, Make, CMake, Git, and zlib development files. APK helpers
use Python 3. Unicorn is fetched on the first build. Use `make JOBS=4` to change
dependency-build parallelism.

## Usage

```sh
./8nomorp --help
./8nomorp context shield.so contexts --apk base.apk
./8nomorp all config.dat decoded patched --apk base.apk --so shield.so
./8nomorp unpack libg.so shield.so base.apk native-output
```

Set `CTXGEN_VERBOSE=1` for emulator diagnostics.

`unpack` detects ARM32/ARM64 automatically. Output directories must be new.

## APK packaging

```sh
python3 tools/build_apk.py --xapk input.xapk --output patched.apk
```

Also accepts `--apkm`, or `--base`, `--native-split`, and `--asset-pack` together.
ARM32-only inputs are selected automatically; `--abi` overrides selection.
Requires Apktool, Java, and Android SDK `zipalign`/`apksigner`. Resource splits
need `--apk-editor APKEditor.jar`. Output is unsigned unless `--keystore` is given.
