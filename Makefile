# Makefile -- self-contained LBTS tool (C99 + libc only for the base build)
#
#   make            -> ./8nomorp         (full offline tool)
#   make unicorn    -> fetches + builds libunicorn under ext/ (once)
#   make 8nomorp    -> ./8nomorp         (full build: offline context
#                                         generation + decrypt --so)
CC      ?= cc
CFLAGS  ?= -O2 -std=c99 -Wall -Wextra
LDLIBS  ?= -lm

UC_DIR    = ext/unicorn
UC_INC    = $(UC_DIR)/include
UC_LIB    = $(UC_DIR)/build/libunicorn.a
UC_CFLAGS = -DWITH_UNICORN -I$(UC_INC)
JOBS      ?= 2
ZLIB_LIB ?= $(shell $(CC) -print-file-name=libz.a)
UC_LIBS   = $(UC_LIB) $(ZLIB_LIB) -lpthread -lm

SRC  = src/main.c src/lbts.c src/promon.c
OBJ  = $(SRC:.c=.o)
GEN_SRC = src/ctxgen.c src/apk.c
GEN_OBJ = $(SRC:.c=.uc.o) $(GEN_SRC:.c=.uc.o)
FULL    = 8nomorp

all: $(FULL)

# ---- full build with the offline emulator (libunicorn) -------------------
unicorn: $(UC_LIB)

$(UC_LIB):
	@mkdir -p ext
	@test -d $(UC_DIR) || git clone --depth 1 -b 2.1.4 \
		https://github.com/unicorn-engine/unicorn $(UC_DIR)
	cmake -S $(UC_DIR) -B $(UC_DIR)/build \
		-DUNICORN_ARCH=aarch64 -DBUILD_SHARED_LIBS=OFF \
		-DUNICORN_ARCHS=aarch64
	$(MAKE) -C $(UC_DIR)/build -j$(JOBS)

%.uc.o: %.c src/lbts.h src/promon.h src/apk.h src/native_impl.h
	$(CC) $(CFLAGS) $(UC_CFLAGS) -I$(UC_INC) -c -o $@ $<

$(FULL): $(UC_LIB) $(GEN_OBJ)
	$(CC) $(CFLAGS) $(UC_CFLAGS) -o $@ $(GEN_OBJ) $(UC_LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ): src/lbts.h src/promon.h

clean:
	rm -f $(FULL) $(OBJ) $(GEN_OBJ) test-promon test-ctxgen test-apk test-guest-runtime probe-native

test: $(UC_LIB)
	$(CC) $(CFLAGS) tools/test_apk.c $(ZLIB_LIB) -o test-apk
	./test-apk
	$(CC) $(CFLAGS) -Isrc tools/test_promon.c src/promon.c -o test-promon
	./test-promon
	$(CC) $(CFLAGS) $(UC_CFLAGS) -Isrc tools/test_ctxgen.c src/lbts.c src/apk.c $(UC_LIBS) -o test-ctxgen
	./test-ctxgen
	$(CC) $(CFLAGS) $(UC_CFLAGS) -Isrc tools/test_guest_runtime.c src/lbts.c src/apk.c $(UC_LIBS) -o test-guest-runtime
	./test-guest-runtime

# Independent export-verifier fixtures; optional development-only Python.
test-native-verifier:
	python3 tools/test_verify_native.py

test-apk-assembly:
	python3 tools/test_assemble.py

test-release-runner:
	python3 tools/test_release_runner.py

test-runtime-monitor:
	python3 tools/test_smoke_waydroid.py

# Slow, local-input integration test; no proprietary fixtures are downloaded.
test-v66-release: $(FULL)
	python3 tools/test_v66_release.py --base "$(V66_BASE)" --shield "$(V66_SHIELD)" --dat "$(V66_DAT)" --output "$(V66_OUTPUT)"

# Version-independent fresh Java integration; hashes record provenance only.
test-release: $(FULL)
	python3 tools/test_release.py --base "$(BASE)" --shield "$(SHIELD)" --output "$(OUTPUT)"

.PHONY: all unicorn clean test test-native-verifier test-apk-assembly test-release-runner test-runtime-monitor test-v66-release test-release
