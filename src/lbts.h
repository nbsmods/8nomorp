/* lbts.h -- LBTS container + protobuf + Promon white-box discovery API.
 *
 * Self-contained: only libc. No OpenSSL / protobuf-c / python / external tools.
 * C99.
 */
#ifndef LBTS_H
#define LBTS_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ======================= self-contained SHA-256 ====================== */
typedef struct {
    uint32_t s[8];
    uint64_t len;
    uint8_t  buf[64];
    size_t   n;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const uint8_t *p, size_t n);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const uint8_t *p, size_t n, uint8_t out[32]);

/* ============================ LBTS container ============================ */
#define LBTS_MAGIC "lbts"
#define LBTS_MAX_CHUNKS 64

struct lbts_chunk {
    uint32_t type;
    uint32_t size;
    const uint8_t *data;   /* points into .raw */
};

struct lbts {
    uint8_t *raw;
    size_t raw_size;
    struct lbts_chunk chunks[LBTS_MAX_CHUNKS];
    int count;
};

/* Parse from an in-memory buffer. Takes ownership semantics: allocates .raw copy. */
int  lbts_parse_buf(struct lbts *out, const uint8_t *buf, size_t n);
int  lbts_parse_file(struct lbts *out, const char *path);
const struct lbts_chunk *lbts_find(const struct lbts *l, uint32_t type);
void lbts_free(struct lbts *l);

/* ============================== protobuf =============================== */
struct pb_field {
    uint32_t number;
    uint32_t wire;
    uint64_t value;        /* varint / 64-bit / length */
    const uint8_t *data;   /* payload ptr for wire 2, or raw bytes for wire 1/5 */
    size_t size;
};

/* Advance *p by one field. Returns 0 ok, -1 malformed. */
int pb_next(const uint8_t **p, const uint8_t *end, struct pb_field *f);

/* Best-effort "looks like a valid protobuf message" test. */
int pb_is_message(const uint8_t *p, size_t size);

/* ============================== envelope =============================== */
/* An authenticated encrypted envelope: IV(16) | ciphertext(N*16) | auth(32). */
struct envelope {
    const uint8_t *iv;      /* 16 */
    const uint8_t *ct;      /* N*16 */
    const uint8_t *auth;    /* 32 */
    size_t ct_len;          /* N*16 */
};

/* Envelope size test: >=64 and (size-48)%16==0, ciphertext >= 1 block. */
static inline int env_is_size(size_t sz) {
    return sz >= 64 && ((sz - 48) % 16) == 0;
}

/* Callback is invoked for each accepted envelope. Return nonzero to stop. */
typedef int (*envelope_cb)(const struct envelope *e, void *ud);
/*
 * Recursively walk a protobuf buffer collecting envelope candidates.
 * Candidates seen only as size-plausible byte strings (not valid messages)
 * go to `on_candidate`; every length-delimited field that parses as a message
 * is descended into. `*count` increments per candidate offered.
 */
int env_walk(const uint8_t *p, size_t size, envelope_cb on_candidate, void *ud);

/* ========================= Promon white-box ============================ */
/* Reference structure (NOT a hard address; discovered at runtime):
 *   - one block routine operating on 16-byte blocks
 *   - a context region ~0x4170 bytes holding 16 lookup tables
 *     each 0x400 bytes (256 x uint32) at context_base + {0x170,0x570,...,0x3D70}
 *
 * Discovery enumerates the image's R_AARCH64_RELATIVE relocations and keeps
 * every target whose data matches that table geometry. Because random data can
 * match the geometry, the winner is chosen by *decryption* (wb_select): only a
 * context whose transform authenticates the container is accepted.
 */
#define WB_MAX_CANDIDATES 64

struct whitebox {
    /* discovery results */
    long  routine_va;        /* virtual address of block routine, -1 if unknown */
    long  context_va;        /* vaddr of context base, -1 if unknown */
    long  context_file_off;  /* file offset of context base, -1 if unknown */
    size_t context_size;     /* e.g. 16752 */
    int   table_count;       /* e.g. 16 */
    size_t table_entry_bytes;/* 4 (uint32) */
    size_t table_entries;    /* 256 */
    size_t table_stride;     /* 0x400 */
    size_t table_base_off;   /* 0x170 within context */
    uint8_t ctx_sha[32];     /* sha256 of the selected context */
    int   ctx_sha_known;     /* 1 if ctx_sha set */
    /* candidate contexts (structural matches, address-independent) */
    int   ncand;
    long  cand_va[WB_MAX_CANDIDATES];
    uint8_t *cand[WB_MAX_CANDIDATES];
    int   selected;          /* index of the decryption-validated context, -1 */
    /* state / capability */
    int   packed;            /* 1 if the routine lives in an encrypted/packed region */
    int   supported;         /* 1 if a decryption algorithm is known for this layout */
    /* extracted material */
    uint8_t *context;        /* owned copy of context bytes */
    uint8_t *routine;        /* owned copy of routine code (may be NULL) */
    size_t routine_len;
    /* human readable notes */
    char note[512];
};

void wb_free(struct whitebox *wb);

/*
 * Analyze an in-memory ELF (.so) image. Locates the white-box routine and its
 * context/tables structurally and fills *wb. Returns 0 on success, 1 if a partial
 * (context found, routine not) result, negative on failure.
 *
 * `want_ctx_sha` (32 bytes, may be NULL) is an optional validation target.
 */
int wb_scan(const uint8_t *so, size_t so_size,
            const uint8_t *want_ctx_sha, struct whitebox *wb);

/*
 * Choose the correct candidate context by decryption. Each candidate is scored
 * by how many of the `probes` envelopes decrypt to a valid PKCS#7 pad on their
 * final block; a candidate must validate at least two (or all probes, when fewer
 * than two are supplied) to be accepted. A wrong context passes one probe with
 * probability ~1/255, so this makes a false accept negligible.
 * Returns 0 and sets wb->selected/wb->context/ctx_sha on success, -1 otherwise.
 */
int wb_select(struct whitebox *wb, const struct envelope *probes, int nprobes);

/* Pretty-print a scan report to `out`. */
void wb_report(const uint8_t *so, size_t so_size, FILE *out);

/* ============================== crypto ================================= */
/*
 * Block transform using the discovered context tables.
 * The exact algorithm (which tables, how combined) is implemented in lbts.c
 * from the reverse-engineered structure. Returns 0 on success.
 */
int wb_block_decrypt(const uint8_t *context, size_t context_size,
                     const uint8_t in[16], uint8_t out[16]);

/*
 * Authentication tag verification. Builds the 32-byte tag the way the format
 * requires. `known_header` is the 256-byte LBTS header blob (field 2 of chunk
 * 0x30) if present, else NULL. Returns 0 if the tag matches, nonzero otherwise,
 * or WB_AUTH_UNSUPPORTED (-2) if the scheme is not known for this version.
 */
#define WB_AUTH_OK          0
#define WB_AUTH_BAD         1
#define WB_AUTH_UNSUPPORTED (-2)
int wb_auth_verify(const uint8_t *context, size_t context_size,
                   const uint8_t *iv, const uint8_t *ct, size_t ct_len,
                   const uint8_t *tag, const uint8_t *known_header,
                   uint8_t out_tag[32]);

/*
 * High-level decrypt of chunk 0x30 body. Fills `plain` (malloc'd, caller frees)
 * with the concatenation of decrypted envelope plaintexts as a nested protobuf
 * stream is optional; here we decrypt each envelope and report.
 */
struct lbts_result {
    int envelopes;        /* candidate envelopes seen */
    int authenticated;    /* passed auth */
    int decrypted;        /* decrypted & padding-valid */
    int unsupported;      /* set if crypto could not be applied */
};

/* Decrypt a single envelope's ciphertext into `out` (>= ct_len). Returns bytes
 * written (>=0), or negative on failure. */
int wb_cbc_decrypt_block(const uint8_t *context, size_t context_size,
                         const uint8_t *iv, const uint8_t *ct, size_t ct_len,
                         uint8_t *out);

#ifdef __cplusplus
}
#endif
#endif /* LBTS_H */
