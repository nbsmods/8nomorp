/*
 * lbts.c -- LBTS container, protobuf walk, envelope discovery, ELF parsing and
 *           the Promon white-box decrypt pipeline.
 *
 * Design rules (hard requirements from the project):
 *   - No hardcoded addresses, chunk sizes, field counts, envelope counts or
 *     context hashes. Everything is discovered structurally.
 *   - The tool never fabricates plaintext. A decryption is only reported when
 *     the recovered transform produces output that validates (authenticated
 *     tag, PKCS#7 padding, protobuf structure).
 *   - If the crypto cannot be safely located, the spec-mandated refusal is
 *     printed instead of guessing.
 *
 * Self-contained: libc only (C99).
 */
#include "lbts.h"
#include "wb_transform.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ============================== helpers ================================ */

static uint32_t rd_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t rd_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static void hex32(const uint8_t b[32], char out[65])
{
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = h[b[i] >> 4];
        out[i * 2 + 1] = h[b[i] & 15];
    }
    out[64] = '\0';
}

static uint8_t *load_file(const char *path, size_t *out_n)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    uint8_t *buf = (uint8_t *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    buf[n] = 0;
    *out_n = (size_t)n;
    return buf;
}

/* ========================= LBTS container ============================= */

int lbts_parse_buf(struct lbts *out, const uint8_t *buf, size_t n)
{
    memset(out, 0, sizeof(*out));
    if (n < 4 || memcmp(buf, LBTS_MAGIC, 4) != 0)
        return -1;

    out->raw = (uint8_t *)malloc(n ? n : 1);
    if (!out->raw) return -1;
    memcpy(out->raw, buf, n);
    out->raw_size = n;

    size_t off = 4;
    while (off + 8 <= out->raw_size && out->count < LBTS_MAX_CHUNKS) {
        uint32_t type = rd_u32(out->raw + off);
        uint32_t size = rd_u32(out->raw + off + 4);
        off += 8;
        if (size > out->raw_size - off) return -1;
        out->chunks[out->count].type = type;
        out->chunks[out->count].size = size;
        out->chunks[out->count].data = out->raw + off;
        out->count++;
        off += size;
    }
    return 0;
}

int lbts_parse_file(struct lbts *out, const char *path)
{
    size_t n;
    uint8_t *b = load_file(path, &n);
    if (!b) return -1;
    int r = lbts_parse_buf(out, b, n);
    free(b);
    return r;
}

const struct lbts_chunk *lbts_find(const struct lbts *l, uint32_t type)
{
    for (int i = 0; i < l->count; i++)
        if (l->chunks[i].type == type) return &l->chunks[i];
    return NULL;
}

void lbts_free(struct lbts *l)
{
    free(l->raw);
    memset(l, 0, sizeof(*l));
}

/* ============================= protobuf =============================== */

static int read_varint(const uint8_t *p, const uint8_t *end, uint64_t *v)
{
    const uint8_t *s = p;
    int shift = 0;
    *v = 0;
    while (p < end && shift < 64) {
        uint8_t b = *p++;
        *v |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) return (int)(p - s);
        shift += 7;
    }
    return -1;
}

int pb_next(const uint8_t **p, const uint8_t *end, struct pb_field *f)
{
    uint64_t key;
    int n = read_varint(*p, end, &key);
    if (n < 0) return -1;
    *p += n;

    f->number = (uint32_t)(key >> 3);
    f->wire   = (uint32_t)(key & 7);
    f->data = NULL; f->size = 0; f->value = 0;

    switch (f->wire) {
    case 0: {
        n = read_varint(*p, end, &f->value);
        if (n < 0) return -1;
        *p += n;
        return 0;
    }
    case 1:
        if (end - *p < 8) return -1;
        f->data = *p; f->size = 8; *p += 8;
        return 0;
    case 2: {
        uint64_t len;
        n = read_varint(*p, end, &len);
        if (n < 0) return -1;
        *p += n;
        if (len > (uint64_t)(end - *p)) return -1;
        f->value = len; f->data = *p; f->size = (size_t)len;
        *p += f->size;
        return 0;
    }
    case 5:
        if (end - *p < 4) return -1;
        f->data = *p; f->size = 4; *p += 4;
        return 0;
    }
    return -1;
}

int pb_is_message(const uint8_t *p, size_t size)
{
    if (size == 0) return 0;
    const uint8_t *cur = p, *end = p + size;
    struct pb_field f;
    int count = 0;
    while (cur < end) {
        if (pb_next(&cur, end, &f) < 0) return 0;
        if (f.number == 0) return 0;
        if (cur > end) return 0;
        count++;
    }
    return cur == end && count > 0;
}

/* =========================== envelope walk ============================ */

int env_walk(const uint8_t *p, size_t size, envelope_cb on_candidate, void *ud)
{
    if (size == 0) return 0;
    const uint8_t *cur = p, *end = p + size;
    struct pb_field f;
    int found = 0;

    while (cur < end) {
        if (pb_next(&cur, end, &f) < 0) break;
        if (f.wire != 2) continue;

        if (env_is_size(f.size) && !pb_is_message(f.data, f.size)) {
            /* A byte string with envelope shape but not itself a message. */
            struct envelope e;
            e.iv     = f.data;
            e.ct     = f.data + 16;
            e.auth   = f.data + f.size - 32;
            e.ct_len = f.size - 48;
            found++;
            if (on_candidate(&e, ud)) return found;
        } else if (pb_is_message(f.data, f.size)) {
            found += env_walk(f.data, f.size, on_candidate, ud);
        }
    }
    return found;
}

/* ============================== ELF reader ============================ */

struct elf_info {
    const uint8_t *img;
    size_t size;
    int machine;
    long shoff;
    int shentsize;
    int shnum;
    long text_va, text_off, text_size;
    int nload;
    struct { long va, filesz, off; } load[16];
};

static int elf_load(struct elf_info *e, const uint8_t *img, size_t size)
{
    memset(e, 0, sizeof(*e));
    if (size < 64 || memcmp(img, "\x7f""ELF", 4) != 0) return -1;
    if (img[4] != 2) return -2;                    /* ELF64 only */
    e->img = img; e->size = size;
    e->machine = rd_u16(img + 18);

    long phoff = (long)rd_u32(img + 32) | ((long)rd_u32(img + 36) << 32);
    uint16_t phentsize = rd_u16(img + 54);
    uint16_t phnum     = rd_u16(img + 56);
    long shoff = (long)rd_u32(img + 40) | ((long)rd_u32(img + 44) << 32);
    e->shentsize = rd_u16(img + 58);
    e->shnum     = rd_u16(img + 60);
    uint16_t shstrndx = rd_u16(img + 62);
    e->shoff = shoff;

    for (uint16_t i = 0; i < phnum && e->nload < 16; i++) {
        long ph = phoff + (long)i * phentsize;
        if (ph + (long)phentsize > (long)size) break;
        if (rd_u32(img + ph) != 1) continue;        /* PT_LOAD */
        e->load[e->nload].va     = (long)rd_u32(img + ph + 16) | ((long)rd_u32(img + ph + 20) << 32);
        e->load[e->nload].off    = (long)rd_u32(img + ph + 8)  | ((long)rd_u32(img + ph + 12) << 32);
        e->load[e->nload].filesz = (long)rd_u32(img + ph + 32) | ((long)rd_u32(img + ph + 36) << 32);
        e->nload++;
    }

    /* .text via the section header table */
    long shstr_off = -1;
    if (shoff && e->shnum && shstrndx < e->shnum) {
        long sh = shoff + (long)shstrndx * e->shentsize;
        if (sh + 64 <= (long)size)
            shstr_off = (long)rd_u32(img + sh + 24) | ((long)rd_u32(img + sh + 28) << 32);
    }
    if (shoff && e->shnum) {
        for (int i = 0; i < e->shnum; i++) {
            long sh = shoff + (long)i * e->shentsize;
            if (sh + (long)e->shentsize > (long)size) break;
            uint32_t name = rd_u32(img + sh);
            if (shstr_off < 0) continue;
            long pos = shstr_off + name;
            if (pos < 0 || pos >= (long)size) continue;
            char nm[16] = {0};
            for (int k = 0; k < 6; k++) {
                if (pos + k >= (long)size) break;
                nm[k] = (char)img[pos + k];
            }
            if (memcmp(nm, ".text", 5) == 0 && nm[5] == 0) {
                e->text_va   = (long)rd_u32(img + sh + 16) | ((long)rd_u32(img + sh + 20) << 32);
                e->text_off  = (long)rd_u32(img + sh + 24) | ((long)rd_u32(img + sh + 28) << 32);
                e->text_size = (long)rd_u32(img + sh + 32) | ((long)rd_u32(img + sh + 36) << 32);
                break;
            }
        }
    }
    return 0;
}

static const uint8_t *va_to_ptr(struct elf_info *e, long va, long len)
{
    for (int i = 0; i < e->nload; i++) {
        long s = e->load[i].va, fs = e->load[i].filesz;
        if (va >= s && va + (len < 0 ? 0 : len) <= s + fs) {
            long delta = e->load[i].off - e->load[i].va;
            return e->img + va + delta;
        }
    }
    return NULL;
}

/* ==================== white-box context discovery ====================
 *
 * The Promon white-box context holds `WB_TABLE_COUNT` lookup tables of
 * `WB_TABLE_ENTRIES` uint32 each, spaced `WB_TABLE_STRIDE` bytes, starting
 * `WB_TABLE_BASE` bytes into the context. The geometry comes from the
 * reference layout; the ADDRESS is discovered without guessing:
 *
 *   The library stores a pointer to the context in its data segment as a
 *   R_AARCH64_RELATIVE relocation. We enumerate the relocation table, and for
 *   every relative reloc whose addend points into a loaded range, test the
 *   table geometry there. Random bytes cannot pass: a *random* reloc points
 *   into code/rodata, not into a run of 16 permutation tables.
 */

#define WB_TABLE_COUNT    16
#define WB_TABLE_ENTRIES  256
#define WB_TABLE_STRIDE   0x400
#define WB_TABLE_BASE     0x170
#define WB_CONTEXT_SIZE   ((size_t)WB_TABLE_BASE + WB_TABLE_COUNT * WB_TABLE_STRIDE)

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

/* A valid white-box table is a bijection on 32-bit words: 256 distinct values. */
static int table_is_permutation(const uint8_t *p)
{
    uint32_t v[WB_TABLE_ENTRIES];
    for (int i = 0; i < WB_TABLE_ENTRIES; i++)
        v[i] = rd_u32(p + (size_t)i * 4);
    qsort(v, WB_TABLE_ENTRIES, sizeof(v[0]), cmp_u32);
    for (int i = 1; i < WB_TABLE_ENTRIES; i++)
        if (v[i] == v[i - 1]) return 0;
    return 1;
}

static int ctx_looks_valid(const uint8_t *p)
{
    if (!table_is_permutation(p + WB_TABLE_BASE)) return 0;
    uint32_t first = rd_u32(p + WB_TABLE_BASE);
    for (int k = 1; k < WB_TABLE_COUNT; k++) {
        const uint8_t *t = p + WB_TABLE_BASE + (size_t)k * WB_TABLE_STRIDE;
        if (!table_is_permutation(t)) return 0;
        if (rd_u32(t) == first) return 0;        /* identical tables -> not a wb ctx */
    }
    return 1;
}

/* Collect the candidate contexts: R_AARCH64_RELATIVE relocs whose target shows
 * the table geometry. Address-independent; the winner is picked by decryption. */
static int collect_ctx_candidates(struct elf_info *e, struct whitebox *wb)
{
    if (e->size < 64) return 0;
    const uint8_t *img = e->img;

    long phoff = (long)rd_u32(img + 32) | ((long)rd_u32(img + 36) << 32);
    uint16_t phentsize = rd_u16(img + 54);
    uint16_t phnum     = rd_u16(img + 56);

    /* PT_DYNAMIC -> DT_RELA / DT_RELASZ */
    long rela = 0, relasz = 0;
    for (uint16_t i = 0; i < phnum; i++) {
        long ph = phoff + (long)i * phentsize;
        if (ph + (long)phentsize > (long)e->size) break;
        if (rd_u32(img + ph) != 2) continue;                 /* PT_DYNAMIC */
        long dyn_va  = (long)rd_u32(img + ph + 16) | ((long)rd_u32(img + ph + 20) << 32);
        long dyn_sz  = (long)rd_u32(img + ph + 32) | ((long)rd_u32(img + ph + 36) << 32);
        const uint8_t *d = va_to_ptr(e, dyn_va, dyn_sz);
        if (!d) break;
        for (long o = 0; o + 16 <= dyn_sz; o += 16) {
            uint64_t tag = (uint64_t)rd_u32(d + o) | ((uint64_t)rd_u32(d + o + 4) << 32);
            uint64_t val = (uint64_t)rd_u32(d + o + 8) | ((uint64_t)rd_u32(d + o + 12) << 32);
            if (tag == 7) rela = (long)val;                  /* DT_RELA */
            if (tag == 8) relasz = (long)val;                /* DT_RELASZ */
            if (tag == 0) break;
        }
        break;
    }
    if (!rela || relasz <= 0) return 0;

    const uint8_t *r = va_to_ptr(e, rela, relasz);
    if (!r) return 0;

    int n = 0;
    for (long o = 0; o + 24 <= relasz && n < WB_MAX_CANDIDATES; o += 24) {
        uint64_t r_info   = (uint64_t)rd_u32(r + o + 8) | ((uint64_t)rd_u32(r + o + 12) << 32);
        int64_t  r_addend = (int64_t)((uint64_t)rd_u32(r + o + 16) | ((uint64_t)rd_u32(r + o + 20) << 32));
        if ((r_info & 0xffffffffu) != 1027) continue;         /* R_AARCH64_RELATIVE */
        if (r_addend <= 0) continue;
        long va = (long)r_addend;
        const uint8_t *p = va_to_ptr(e, va, (long)WB_CONTEXT_SIZE);
        if (!p) continue;
        if (!ctx_looks_valid(p)) continue;
        wb->cand_va[n] = va;
        wb->cand[n] = (uint8_t *)malloc(WB_CONTEXT_SIZE);
        if (!wb->cand[n]) break;
        memcpy(wb->cand[n], p, WB_CONTEXT_SIZE);
        n++;
    }
    wb->ncand = n;
    return n;
}

static double region_entropy(const uint8_t *p, long n)
{
    if (n <= 0) return 0;
    long counts[256];
    memset(counts, 0, sizeof(counts));
    long step = n > 262144 ? n / 262144 : 1;
    long total = 0;
    for (long i = 0; i < n; i += step) { counts[p[i]]++; total++; }
    double e = 0;
    for (int c = 0; c < 256; c++) {
        if (counts[c]) {
            double pr = (double)counts[c] / (double)total;
            e -= pr * (log(pr) / log(2.0));
        }
    }
    return e;
}

void wb_free(struct whitebox *wb)
{
    /* wb->context aliases one of the candidate buffers, so free only the
     * candidates (each exactly once). */
    for (int i = 0; i < wb->ncand; i++) {
        free(wb->cand[i]);
        wb->cand[i] = NULL;
    }
    free(wb->routine);
    memset(wb, 0, sizeof(*wb));
    wb->routine_va = wb->context_va = wb->context_file_off = -1;
    wb->selected = -1;
}

int wb_scan(const uint8_t *so, size_t so_size, const uint8_t *want_ctx_sha,
            struct whitebox *wb)
{
    memset(wb, 0, sizeof(*wb));
    wb->routine_va = wb->context_va = wb->context_file_off = -1;
    wb->selected = -1;

    wb->context_size      = WB_CONTEXT_SIZE;
    wb->table_count       = WB_TABLE_COUNT;
    wb->table_entry_bytes = 4;
    wb->table_entries     = WB_TABLE_ENTRIES;
    wb->table_stride      = WB_TABLE_STRIDE;
    wb->table_base_off    = WB_TABLE_BASE;

    struct elf_info e;
    if (elf_load(&e, so, so_size) < 0) return -1;
    if (e.machine != 0xB7) {
        snprintf(wb->note, sizeof wb->note, "not AArch64 (e_machine=0x%x)", e.machine);
        return -1;
    }

    if (e.text_off && e.text_size) {
        const uint8_t *tp = va_to_ptr(&e, e.text_va, e.text_size);
        if (tp) {
            double en = region_entropy(tp, e.text_size);
            wb->packed = (en > 7.0);
        }
    }

    int n = collect_ctx_candidates(&e, wb);

    if (n == 1) {
        /* A single structural match: adopt it (still validated by decryption). */
        wb->selected = 0;
        wb->context = wb->cand[0];
        wb->context_va = wb->cand_va[0];
        wb->context_file_off = va_to_ptr(&e, wb->cand_va[0], 0) - so;
        sha256(wb->context, WB_CONTEXT_SIZE, wb->ctx_sha);
        wb->ctx_sha_known = 1;
    }

    if (wb->context && want_ctx_sha && memcmp(wb->ctx_sha, want_ctx_sha, 32) == 0)
        wb->supported = 1;

    if (n <= 0) {
        snprintf(wb->note, sizeof wb->note,
                 "no white-box context candidate (relocation-referenced) in the static image");
    } else if (n == 1) {
        snprintf(wb->note, sizeof wb->note,
                 "one candidate context at va 0x%lx (validated by decryption)", wb->context_va);
    } else {
        snprintf(wb->note, sizeof wb->note,
                 "%d candidate contexts; the correct one is selected by decryption", n);
    }

    return wb->context ? 0 : 1;
}

/* Select only authenticated contexts; padding alone is not authentication. */
static int ctx_validates_envelope(const uint8_t *ctx, const struct envelope *e)
{
    if (e->ct_len < 16 || e->ct_len % 16) return 0;
    if (wb_auth_verify(ctx, WB_CONTEXT_SIZE, e->iv, e->ct, e->ct_len,
                       e->auth, NULL, NULL) != WB_AUTH_OK) return 0;
    uint8_t w[16];
    wb_transform(ctx, e->ct + e->ct_len - 16, w);
    const uint8_t *prev = e->ct_len == 16 ? e->iv : e->ct + e->ct_len - 32;
    for (int k = 0; k < 16; k++) w[k] ^= prev[k];
    uint8_t pad = w[15];
    if (pad < 1 || pad > 16) return 0;
    for (int k = 0; k < pad; k++)
        if (w[15 - k] != pad) return 0;
    return 1;
}

int wb_select(struct whitebox *wb, const struct envelope *probes, int nprobes)
{
    if (!wb || wb->ncand <= 0 || !probes || nprobes <= 0) return -1;

    int needed = nprobes >= 2 ? 2 : 1;
    int best = -1, best_score = 0;

    for (int i = 0; i < wb->ncand; i++) {
        int score = 0;
        for (int k = 0; k < nprobes; k++)
            score += ctx_validates_envelope(wb->cand[i], &probes[k]);
        if (score > best_score) { best_score = score; best = i; }
        if (score == nprobes && nprobes >= 2) break;   /* perfect score: stop */
    }
    if (best < 0 || best_score < needed) return -1;

    wb->selected = best;
    wb->context = wb->cand[best];
    wb->context_va = wb->cand_va[best];
    sha256(wb->context, WB_CONTEXT_SIZE, wb->ctx_sha);
    wb->ctx_sha_known = 1;
    wb->supported = 1;
    snprintf(wb->note, sizeof wb->note,
             "context at va 0x%lx selected (%d/%d probe envelopes validated)",
             wb->context_va, best_score, nprobes);
    return 0;
}

void wb_report(const uint8_t *so, size_t so_size, FILE *out)
{
    struct whitebox wb;
    memset(&wb, 0, sizeof wb);
    wb.routine_va = wb.context_va = wb.context_file_off = -1;

    struct elf_info e;
    int er = elf_load(&e, so, so_size);

    fprintf(out, "ELF loaded: %s\n", er >= 0 ? "yes" : "no");
    if (er < 0) { fprintf(out, "not a supported ELF64 image\n"); return; }
    fprintf(out, "architecture: %s\n", e.machine == 0xB7 ? "AArch64 (ARM64)" : "other");
    if (e.text_off)
        fprintf(out, ".text: va=0x%lx off=0x%lx size=0x%lx\n",
                e.text_va, e.text_off, e.text_size);

    wb_scan(so, so_size, NULL, &wb);

    char sha[65] = "-";
    if (wb.ctx_sha_known) hex32(wb.ctx_sha, sha);

    fprintf(out, "packed executable: %s\n", wb.packed ? "yes" : "no");
    fprintf(out, "white-box context candidates: %d\n", wb.ncand);
    if (wb.ncand > 0) {
        fprintf(out, "  first candidate va: 0x%lx\n", wb.cand_va[0]);
        fprintf(out, "  tables            : %d x %zu x uint32, stride 0x%zx, base +0x%zx\n",
                wb.table_count, wb.table_entries, wb.table_stride, wb.table_base_off);
        fprintf(out, "  size              : %zu\n", wb.context_size);
    }
    if (wb.context) {
        fprintf(out, "selected context:\n");
        fprintf(out, "  va        : 0x%lx\n", wb.context_va);
        fprintf(out, "  file off  : 0x%lx\n", wb.context_file_off);
        fprintf(out, "  sha-256   : %s\n", sha);
    } else {
        fprintf(out, "selected context: none (chosen by decryption; run `decrypt`)\n");
    }
    fprintf(out, "crypto supportable: %s\n", wb.supported ? "yes (validated context)" : "no (no validated context)");
    if (wb.note[0]) fprintf(out, "note: %s\n", wb.note);
    wb_free(&wb);
}

/* ============================== crypto ================================ */

int wb_block_decrypt(const uint8_t *context, size_t context_size,
                     const uint8_t in[16], uint8_t out[16])
{
    if (!context || context_size < WB_CONTEXT_SIZE) return -1;
    wb_transform(context, in, out);
    return 0;
}

/*
 * Recovered gate: SHA256(IV || ciphertext) is compared with two independently
 * white-box-decrypted trailer blocks. The hash helpers previously mistaken for
 * protobuf routines are SHA256_Init/Update/Final: their initial state is the
 * eight standard SHA-256 words, with 64-byte blocks and big-endian final output.
 * No inverse transform is required for verification.
 */
static int wb_tag(const uint8_t *iv, const uint8_t *ct, size_t ct_len,
                  uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, iv, 16);
    sha256_update(&c, ct, ct_len);
    sha256_final(&c, out);
    return 0;
}

int wb_auth_verify(const uint8_t *context, size_t context_size,
                   const uint8_t *iv, const uint8_t *ct, size_t ct_len,
                   const uint8_t *tag, const uint8_t *known_header,
                   uint8_t out_tag[32])
{
    (void)known_header;
    if (!iv || !ct || ct_len == 0 || ct_len % 16 || !tag) return WB_AUTH_BAD;
    if (!context || context_size < WB_CONTEXT_SIZE) return WB_AUTH_UNSUPPORTED;
    uint8_t mine[32], decoded[32];
    if (wb_tag(iv, ct, ct_len, mine) < 0) return WB_AUTH_UNSUPPORTED;
    if (wb_block_decrypt(context, context_size, tag, decoded) < 0 ||
        wb_block_decrypt(context, context_size, tag + 16, decoded + 16) < 0)
        return WB_AUTH_UNSUPPORTED;
    if (out_tag) memcpy(out_tag, mine, 32);

    unsigned d = 0;
    for (int i = 0; i < 32; i++) d |= (unsigned)(mine[i] ^ decoded[i]);
    return d == 0 ? WB_AUTH_OK : WB_AUTH_BAD;
}

int wb_cbc_decrypt_block(const uint8_t *context, size_t context_size,
                         const uint8_t *iv, const uint8_t *ct, size_t ct_len,
                         uint8_t *out)
{
    if (!context || ct_len == 0 || (ct_len % 16) != 0) return -1;

    uint8_t prev[16];
    memcpy(prev, iv, 16);

    for (size_t b = 0; b < ct_len; b += 16) {
        uint8_t w[16];
        if (wb_block_decrypt(context, context_size, ct + b, w) < 0) return -1;
        for (int i = 0; i < 16; i++)
            out[b + i] = w[i] ^ prev[i];
        memcpy(prev, ct + b, 16);
    }

    /* PKCS#7 */
    uint8_t pad = out[ct_len - 1];
    if (pad == 0 || pad > 16) return -1;
    for (uint8_t i = 0; i < pad; i++)
        if (out[ct_len - 1 - i] != pad) return -1;

    return (int)(ct_len - pad);
}

/* ======================= self-contained SHA-256 ======================= */

static const uint32_t SHA256_K[64] = {
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define SH_ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))

static void sha256_priv(sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|
               ((uint32_t)p[i*4+2]<<8)|p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = SH_ROR(w[i-15],7) ^ SH_ROR(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = SH_ROR(w[i-2],17) ^ SH_ROR(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->s[0],b=c->s[1],cc=c->s[2],d=c->s[3];
    uint32_t e=c->s[4],f=c->s[5],g=c->s[6],h=c->s[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = SH_ROR(e,6) ^ SH_ROR(e,11) ^ SH_ROR(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = SH_ROR(a,2) ^ SH_ROR(a,13) ^ SH_ROR(a,22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->s[0]+=a; c->s[1]+=b; c->s[2]+=cc; c->s[3]+=d;
    c->s[4]+=e; c->s[5]+=f; c->s[6]+=g; c->s[7]+=h;
}

void sha256_init(sha256_ctx *c)
{
    c->s[0]=0x6a09e667; c->s[1]=0xbb67ae85; c->s[2]=0x3c6ef372; c->s[3]=0xa54ff53a;
    c->s[4]=0x510e527f; c->s[5]=0x9b05688c; c->s[6]=0x1f83d9ab; c->s[7]=0x5be0cd19;
    c->len=0; c->n=0;
}

void sha256_update(sha256_ctx *c, const uint8_t *p, size_t n)
{
    c->len += n;
    while (n) {
        size_t k = 64 - c->n;
        if (k > n) k = n;
        memcpy(c->buf + c->n, p, k);
        c->n += k; p += k; n -= k;
        if (c->n == 64) { sha256_priv(c, c->buf); c->n = 0; }
    }
}

void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t z = 0;
    while (c->n != 56) sha256_update(c, &z, 1);
    uint8_t L[8];
    for (int i = 0; i < 8; i++) L[i] = (uint8_t)(bits >> (56 - 8*i));
    sha256_update(c, L, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->s[i] >> 24);
        out[i*4+1] = (uint8_t)(c->s[i] >> 16);
        out[i*4+2] = (uint8_t)(c->s[i] >> 8);
        out[i*4+3] = (uint8_t)(c->s[i]);
    }
}

void sha256(const uint8_t *p, size_t n, uint8_t out[32])
{
    sha256_ctx c; sha256_init(&c); sha256_update(&c, p, n); sha256_final(&c, out);
}
