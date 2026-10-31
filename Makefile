# Build the offline tool and its command-line helpers.
CC      ?= cc
CFLAGS  ?= -O2 -std=c99 -Wall -Wextra

UC_DIR    = ext/unicorn
UC_INC    = $(UC_DIR)/include
UC_LIB    = $(UC_DIR)/build/libunicorn.a
UC_CONFIG = $(UC_DIR)/build/.8nomorp-architectures
UC_CFLAGS = -DWITH_UNICORN -I$(UC_INC)
JOBS      ?= 2
ZLIB_LIB ?= $(shell $(CC) -print-file-name=libz.a)
ifeq ($(ZLIB_LIB),libz.a)
ZLIB_LIB = -lz
endif
UC_LIBS   = $(UC_LIB) $(ZLIB_LIB) -lpthread -lm

SRC  = src/main.c src/lbts.c src/promon.c src/attestation.c
GEN_SRC = src/ctxgen.c src/apk.c
GEN_OBJ = $(SRC:.c=.uc.o) $(GEN_SRC:.c=.uc.o)
DEP = $(GEN_OBJ:.o=.d)
FULL    = 8nomorp

all: $(FULL)

# ---- full build with the offline emulator (libunicorn) -------------------
unicorn: $(UC_LIB)

$(UC_CONFIG): Makefile
	@mkdir -p ext
	@test -d $(UC_DIR) || git clone --depth 1 -b 2.1.4 \
		https://github.com/unicorn-engine/unicorn $(UC_DIR)
	cmake -S $(UC_DIR) -B $(UC_DIR)/build \
		-DUNICORN_ARCH="aarch64;arm" -DBUILD_SHARED_LIBS=OFF
	@touch $@

$(UC_LIB): $(UC_CONFIG)
	$(MAKE) -C $(UC_DIR)/build -j$(JOBS)
	@touch $@

%.uc.o: %.c | $(UC_LIB)
	$(CC) $(CFLAGS) $(UC_CFLAGS) -MMD -MP -c -o $@ $<

-include $(DEP)

$(FULL): $(UC_LIB) $(GEN_OBJ)
	$(CC) $(CFLAGS) $(UC_CFLAGS) -o $@ $(GEN_OBJ) $(UC_LIBS)

clean:
	rm -f $(FULL) $(GEN_OBJ) $(DEP)

check: all
	./$(FULL) --help
	python3 tools/build_apk.py --help
	python3 tools/assemble.py --help

.PHONY: all unicorn clean check
