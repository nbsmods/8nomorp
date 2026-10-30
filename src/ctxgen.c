/*
 * ctxgen.c -- offline white-box context generator for the Promon SHIELD'd
 * libsupercell_brawlstars.so, built on libunicorn (AArch64).
 *
 * C port of tools/unpack.py + tools/probe_live_generator.py.  It runs the
 * protector's own startup (init_array constructor + JNI_OnLoad) inside an
 * emulator, captures the code/rodata regions the constructor decrypts in
 * place, then re-runs the freshly decrypted context generators and captures
 * the white-box table set they produce.
 *
 * Nothing is hardcoded per version:
 *   - constructor = DT_INIT_ARRAY[0]            (read after relocation)
 *   - JNI entry   = exported "JNI_OnLoad"       (dynsym lookup)
 *   - decrypted regions = memory diff before/after the run
 *   - generator entries = structural prologue scan of the decrypted code
 *
 * Output: one or more candidate context blobs (ctx_<n>.bin).  The caller
 * (`lbts decrypt --so ...`) picks the one that authenticates the container.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <unicorn/unicorn.h>
#include <unicorn/arm64.h>
#include "apk.h"
#include <zlib.h>

/* memory layout (arbitrary, but non-clashing with the .so image) */
#define STACK_TOP   0x41000000ULL
#define STACK_SIZE  0x01000000ULL
#define HEAP_BASE   0x50000000ULL
#define HEAP_SIZE   0x10000000ULL
#define TLS_BASE    0x30000000ULL
#define TLS_SIZE    0x10000ULL
#define STUB_BASE   0x20000000ULL
#define STUB_SIZE   0x01000000ULL
#define MISC_BASE   0x18000000ULL
#define MISC_SIZE   0x01000000ULL
#define JNI_VM     (MISC_BASE+0x800000)
#define JNI_ENV    (MISC_BASE+0x801000)
#define JNI_TABLE  (MISC_BASE+0x802000)
#define JVM_TABLE  (MISC_BASE+0x803000)
#define LIBC_BASE   0x7f00000000ULL
#define MMAP_BASE   0x60000000ULL
#define CTXSTACK_BASE 0x43000000ULL
#define CTXSTACK_SIZE 0x00200000ULL
#define CTXTLS_BASE   0x31000000ULL
#define CTXTLS_SIZE   0x00010000ULL

#define SENT_CTOR   0xdeadbeef00000000ULL
#define SENT_JNI    0xdeadbeef00000001ULL

#define MAX_STUBS   1024
#define MAX_FILES   64
#define MAX_BLOCKS  65536
#define MAX_REGIONS 256

#define MAX_THREADS    8
#define MAX_CHANS      16
#define CHAN_SIZE      8192
#define THREAD_QUANTUM 4000000ULL
#define SENT_THREAD    0xdeadbeef00000002ULL

static int g_verbose = 0;
#define VLOG(...) do{ if(g_verbose) fprintf(stderr, __VA_ARGS__); }while(0)

typedef struct { uint64_t va, off, filesz, memsz; uint32_t flags; } seg_t;
typedef struct { uint64_t addr; char name[56]; } stub_t;
typedef struct { int kind; int fd; int rnd; char path[512]; char *content; size_t len, pos; } fakefile_t;
typedef struct { uint64_t ptr, size; } heapblock_t;
typedef struct { uint64_t va; size_t len; uint8_t *data; } region_t;

/* cooperative thread: the protector starts workers via pthread_create and
 * synchronises over pipes/socketpairs.  We cannot run real threads inside
 * one unicorn instance, so threads are scheduled at blocking points. */
typedef struct {
    int      state;                 /* 0 free | 1 runnable | 2 blocked | 3 done */
    uint64_t regs[31];              /* x0..x30 */
    uint64_t sp, pc, tls;
    uint32_t pid, ppid;
    region_t *fork_mem;
    int nfork_mem;
    uint64_t fork_heap_next;
    uc_context *cpu;
    uint64_t bfd, bbuf, blen;       /* pending (blocked) read */
    int wait_pid;
    uint64_t wait_status;
} thread_t;

/* pipe/socketpair endpoint pair with a single data buffer */
typedef struct { int used, rfd, wfd; uint8_t buf[CHAN_SIZE]; size_t len; } chan_t;
typedef struct { uint64_t callback,data,lr;unsigned next; } phdr_call_t;
typedef struct { uint64_t guest;z_stream stream;int active; } inflate_call_t;

typedef struct emu {
    uc_engine *uc;
    struct emu *imports, *peer;
    uint64_t load_bias;
    const char *image_name;
    uint8_t *apk; size_t apk_len;
    struct apk_metadata package;
    uint8_t   *raw; size_t raw_len;
    seg_t      segs[8]; int nsegs;
    uint64_t   symtab, strtab; int nsyms; char **symnames;
    stub_t     stubs[MAX_STUBS]; int nstubs;
    uint64_t   heap_next;
    heapblock_t blocks[MAX_BLOCKS]; int nblocks;
    uint64_t   mmap_next;
    uint64_t   errno_addr, file_next;
    fakefile_t files[MAX_FILES]; int nfiles;
    chan_t     chans[MAX_CHANS]; int nchans;
    int        next_fd;
    thread_t   th[MAX_THREADS]; int nth;
    int        cur_ctx;                 /* 0 = main thread, 1..n = th[n-1] */
    uint32_t   trace_pid;               /* process stopped by emulated ptrace */
    uint32_t   tracer_pid;
    char status_content[1024];
    uint32_t   trace_status;
    int        trace_pending, trace_stopped;
    uc_context *trace_cpu;
    region_t   *trace_mem;
    int        trace_mem_count;
    struct { int active; uint64_t fd, buf, len; } blk;   /* main blocked read */
    uint8_t   *fake_so; size_t fake_so_len;
    int        stop;
    uint64_t   insn_count;
    uint64_t   import_calls;
    uint64_t   clock_ns;
    uint64_t   startup_budget; /* zero selects the context generator's default */
    uint64_t   thread_values[MAX_THREADS+1][128];
    int        yield_workers; /* main condition wait gives runnable workers a quantum */
    unsigned   next_key;
    phdr_call_t phdr_calls[MAX_THREADS+1][8];
    unsigned phdr_depth[MAX_THREADS+1];
    inflate_call_t inflaters[16];
    struct { char owner[256],name[128],signature[128];uint64_t id,value; } static_fields[128];
    unsigned nstatic_fields;
    struct { char owner[256],name[128],signature[256];uint64_t function; } natives[256];
    unsigned nnatives;
    uint64_t accessibility_listener;
    uint64_t lifecycle_listener;
    struct { uint64_t object,value;char field[128]; } object_fields[128];
    unsigned nobject_fields;
    struct { uint64_t object,lr; } constructors[MAX_THREADS+1][8];
    unsigned constructor_depth[MAX_THREADS+1];
    uint8_t   *captures[16]; int ncaptures;
    size_t     capture_size[16];
    uint64_t   capture_site[16];
    uint64_t   capture_entry[16];
} emu_t;

/* ------------------------------------------------------------------ */
/* ELF helpers                                                         */

static uint64_t rd64(const uint8_t *b, size_t off){ uint64_t v; memcpy(&v,b+off,8); return v; }
static uint32_t rd32(const uint8_t *b, size_t off){ uint32_t v; memcpy(&v,b+off,4); return v; }

static int elf_load(emu_t *e){
    const uint8_t *raw = e->raw;
    if(e->raw_len < 64 || memcmp(raw, "\x7f""ELF", 4) != 0) return -1;
    if(raw[4] != 2) return -1;                       /* ELFCLASS64 */
    uint64_t phoff = rd64(raw, 0x20);
    uint32_t phentsize = rd32(raw, 54) & 0xffff;     /* e_phentsize @54 */
    uint32_t phnum = (rd32(raw, 54) >> 16) & 0xffff; /* e_phnum @56 */
    if(phentsize != 56 || !phnum || phnum > 16) return -1;

    for(uint32_t i = 0; i < phnum; i++){
        size_t p = phoff + i*56;
        if(p + 56 > e->raw_len) break;
        uint32_t type = rd32(raw, p);
        if(type == 1 && e->nsegs < 8){
            seg_t *s = &e->segs[e->nsegs++];
            s->off = rd64(raw, p+8);
            s->va = rd64(raw, p+16);
            s->filesz = rd64(raw, p+32);
            s->memsz = rd64(raw, p+40);
            s->flags = rd32(raw, p+4);
        }
    }
    return e->nsegs ? 0 : -1;
}

static long va2file(const emu_t *e, uint64_t va){
    for(int s = 0; s < e->nsegs; s++)
        if(va >= e->segs[s].va && va < e->segs[s].va + e->segs[s].filesz)
            return (long)(va - e->segs[s].va + e->segs[s].off);
    return -1;
}

/* walk PT_DYNAMIC collecting tags */
static int dyn_tags(const emu_t *e, uint64_t *tags){
    long dfo = va2file(e, 0), tmp = 0;
    /* find PT_DYNAMIC va/sz */
    const uint8_t *raw = e->raw;
    uint64_t phoff = rd64(raw, 0x20);
    uint32_t phnum = (rd32(raw, 54) >> 16) & 0xffff;
    uint64_t dva = 0, dsz = 0;
    for(uint32_t i = 0; i < phnum; i++){
        size_t p = phoff + i*56;
        if(rd32(raw, p) == 2){ dva = rd64(raw, p+16); dsz = rd64(raw, p+32); break; }
    }
    if(!dva) return -1;
    long fo = va2file(e, dva);
    if(fo < 0) return -1;
    (void)tmp; (void)dfo;
    for(size_t k = 0; k < dsz/16; k++){
        uint64_t tag = rd64(raw, (size_t)fo + k*16);
        uint64_t val = rd64(raw, (size_t)fo + k*16 + 8);
        if(tag == 0) break;
        if(tag < 64) tags[tag] = val;
    }
    return 0;
}

static uint64_t dyn_value(const emu_t *e, uint64_t wanted){
    uint64_t phoff=rd64(e->raw,32);
    unsigned phnum=(rd32(e->raw,54)>>16)&0xffff;
    for(unsigned i=0;i<phnum;i++){
        size_t p=(size_t)phoff+i*56;
        if(p+56>e->raw_len || rd32(e->raw,p)!=2) continue;
        uint64_t off=rd64(e->raw,p+8),len=rd64(e->raw,p+32);
        if(off>e->raw_len || len>e->raw_len-off) return 0;
        for(uint64_t j=0;j+16<=len;j+=16){
            uint64_t tag=rd64(e->raw,(size_t)(off+j));
            if(!tag) break;
            if(tag==wanted) return rd64(e->raw,(size_t)(off+j+8));
        }
    }
    return 0;
}

static const char *symname(const emu_t *e, int idx){
    if(!e->symnames || idx < 0 || idx >= e->nsyms) return "";
    return e->symnames[idx] ? e->symnames[idx] : "";
}

static void elf_syms(emu_t *e){
    uint64_t tags[64]; memset(tags, 0, sizeof tags);
    if(dyn_tags(e, tags) < 0) return;
    e->symtab = tags[6]; e->strtab = tags[5];
    long hf = va2file(e, tags[4]);                  /* DT_HASH */
    VLOG("[*] dyn: symtab=0x%llx strtab=0x%llx hash=0x%llx (file %ld)\n",
         (unsigned long long)e->symtab,(unsigned long long)e->strtab,
         (unsigned long long)tags[4],hf);
    if(e->symtab == 0 || e->strtab == 0) return;
    long nchain=0;
    if(tags[4] && hf>=0 && (size_t)hf+8<=e->raw_len)
        nchain=(long)rd32(e->raw,(size_t)hf+4);
    else {
        uint64_t gnu_hash=dyn_value(e,0x6ffffef5); /* DT_GNU_HASH */
        if(!gnu_hash)return;
        long gh=va2file(e,gnu_hash);
        if(gh<0 || (size_t)gh+16>e->raw_len) return;
        uint32_t nb=rd32(e->raw,(size_t)gh),first=rd32(e->raw,(size_t)gh+4),
                 bloom=rd32(e->raw,(size_t)gh+8);
        uint64_t buckets=(uint64_t)gh+16+(uint64_t)bloom*8;
        uint64_t chains=buckets+(uint64_t)nb*4;
        if(first>65536 || chains>e->raw_len) return;
        uint32_t last=0;
        for(uint32_t i=0;i<nb;i++){
            uint32_t v=rd32(e->raw,(size_t)buckets+i*4);
            if(v && v<first)return;
            if(v>last) last=v;
        }
        if(last>65536) return;
        if(!last) nchain=first;
        else for(uint32_t i=last;i<65536;i++){
            uint64_t pos=chains+(uint64_t)(i-first)*4;
            if(pos+4>e->raw_len) return;
            if(rd32(e->raw,(size_t)pos)&1){ nchain=i+1;break; }
        }
    }
    if(nchain <= 0 || nchain > 65536) return;
    long sf = va2file(e, e->symtab), stf = va2file(e, e->strtab);
    if(sf < 0 || stf < 0) return;
    e->nsyms = (int)nchain;
    e->symnames = (char **)calloc((size_t)e->nsyms, sizeof(char *));
    for(int i = 0; i < e->nsyms; i++){
        size_t so = (size_t)sf + (size_t)i*24;
        if(so + 24 > e->raw_len){ e->nsyms = i; break; }
        uint32_t nameoff = rd32(e->raw, so);
        if(!nameoff){ e->symnames[i] = strdup(""); continue; }
        size_t p = (size_t)stf + nameoff;
        if(p >= e->raw_len){ e->symnames[i] = strdup(""); continue; }
        const uint8_t *z = memchr(e->raw + p, 0, e->raw_len - p);
        size_t l = z ? (size_t)(z - (e->raw + p)) : 0;
        char *s = (char *)malloc(l+1);
        memcpy(s, e->raw + p, l); s[l] = 0;
        e->symnames[i] = s;
    }
}

/* ------------------------------------------------------------------ */
/* stub registry                                                       */

static uint64_t stub_new(emu_t *e, const char *name){
    if(e->nstubs >= MAX_STUBS) return 0;
    stub_t *s = &e->stubs[e->nstubs];
    s->addr = STUB_BASE + (uint64_t)e->nstubs * 0x10;
    snprintf(s->name, sizeof s->name, "%s", name);
    e->nstubs++;
    return s->addr;
}

static uint64_t stub_for(emu_t *e, const char *name){
    if(e->imports) return stub_for(e->imports,name);
    for(int i = 0; i < e->nstubs; i++)
        if(!strcmp(e->stubs[i].name, name)) return e->stubs[i].addr;
    return stub_new(e, name);
}

/* ------------------------------------------------------------------ */
/* fake system files                                                   */

typedef struct { const char *package,*apk,*native,*data,*files,*cache,*comm; } game_t;
#define GAME(n) {"com.supercell." n,"/data/app/com.supercell." n "/base.apk", "/data/app/org.supercell." n "/lib/arm64", "/data/user/0/com.supercell." n, "/data/user/0/com.supercell." n "/files", "/data/user/0/com.supercell." n "/cache",n "\n"}
static const game_t games[]={GAME("brawlstars"),GAME("clashofclans"),GAME("clashroyale"),GAME("moco"),
                             GAME("squad"),GAME("hayday"),GAME("boombeach")};
#undef GAME
static const game_t *guest_game(const emu_t *e){
    for(const emu_t *m=e;m;m=m==e?e->peer:NULL){
        for(unsigned i=0;i<sizeof games/sizeof games[0];i++)
            if(!strcmp(m->package.package,games[i].package))return &games[i];
        if(m->image_name)for(unsigned i=0;i<sizeof games/sizeof games[0];i++){
            char shield[128];snprintf(shield,sizeof shield,"libsupercell_%s.so",strrchr(games[i].package,'.')+1);
            if(!strcmp(m->image_name,shield))return &games[i];
        }
    }
    return &games[0];
}

static char *build_maps(const emu_t *e, size_t *outn){
    size_t cap = 16384; char *buf = (char *)malloc(cap); size_t n = 0;
    for(const emu_t *m=e;m;m=m==e ? e->peer : NULL){
    const char *shown=m->image_name ? m->image_name : "libsupercell_brawlstars.so";
    for(int i = 0; i < m->nsegs; i++){
        const seg_t *s = &m->segs[i];
        uint64_t b0 = (s->va+m->load_bias) & ~0xfffULL;
        uint64_t e0 = (s->va+m->load_bias + s->memsz + 0xfff) & ~0xfffULL;
        char perms[5];
        perms[0] = 'r'; perms[1] = (s->flags & 2) ? 'w' : '-';
        perms[2] = (s->flags & 1) ? 'x' : '-'; perms[3] = 'p'; perms[4] = 0;
        n += (size_t)snprintf(buf+n, cap-n, "%016llx-%016llx %s %06llx 00:01 12345 %s/%s\n",
             (unsigned long long)b0, (unsigned long long)e0, perms,
               (unsigned long long)(s->off & ~0xfffULL), guest_game(e)->native, shown);
    }
    }
    n += (size_t)snprintf(buf+n, cap-n,
        "%016llx-%016llx r-xp 00000000 00:01 999 /system/lib64/libc.so\n"
        "%016llx-%016llx r--p 00200000 00:01 999 /system/lib64/libc.so\n"
        "%016llx-%016llx rw-p 00220000 00:01 999 /system/lib64/libc.so\n"
        "%016llx-%016llx r-xp 00000000 00:01 998 /system/lib64/libm.so\n"
        "%016llx-%016llx r-xp 00000000 00:01 997 /system/lib64/libdl.so\n"
        "%016llx-%016llx r-xp 00000000 00:01 996 /system/lib64/liblog.so\n"
        "%016llx-%016llx r-xp 00000000 00:01 995 /system/lib64/libz.so\n"
        "%016llx-%016llx r-xp 00000000 00:01 994 /system/lib64/libart.so\n"
        "%016llx-%016llx r-xp 00000000 00:00 0 /system/bin/linker64\n"
        "%016llx-%016llx rw-p 00000000 00:00 0 [stack]\n",
        (unsigned long long)LIBC_BASE, (unsigned long long)(LIBC_BASE+0x200000),
        (unsigned long long)(LIBC_BASE+0x200000), (unsigned long long)(LIBC_BASE+0x220000),
        (unsigned long long)(LIBC_BASE+0x220000), (unsigned long long)(LIBC_BASE+0x230000),
        (unsigned long long)(LIBC_BASE+0x300000), (unsigned long long)(LIBC_BASE+0x400000),
        (unsigned long long)(LIBC_BASE+0x500000), (unsigned long long)(LIBC_BASE+0x600000),
        (unsigned long long)(LIBC_BASE+0x700000), (unsigned long long)(LIBC_BASE+0x800000),
        (unsigned long long)(LIBC_BASE+0x900000), (unsigned long long)(LIBC_BASE+0xa00000),
        (unsigned long long)(LIBC_BASE+0xa00000), (unsigned long long)(LIBC_BASE+0xc00000),
        0x7fe0000000ULL, 0x7ff0000000ULL, 0x7fff000000ULL, 0x7fffffffffULL);
    buf[n] = 0;
    *outn = n;
    return buf;
}

static const char *STATUS_CONTENT =
    "Name:\torg.supercell.brawlstars\n"
    "State:\tR (running)\n"
    "Tgid:\t1234\n"
    "Pid:\t1234\n"
    "PPid:\t500\n"
    "TracerPid:\t0\n"
    "Uid:\t10123\t10123\t10123\t10123\n"
    "Gid:\t10123\t10123\t10123\t10123\n";

static const char *RESOLVE_FUNCS[] = {
    "read", "open", "exit", "malloc", "mmap", "munmap", "free",
    "close", "lseek", "mprotect", "sysconf", "strstr", "cacheflush",
    "__system_property_get", "dladdr", "execl", "inotify_add_watch",
    "syscall", "dl_iterate_phdr", "dlopen", "eventfd", "inotify_init",
    "fork", "prctl", "killpg", "fgets", "fopen", "sscanf", "fclose"
};
#define NRESOLVE (int)(sizeof RESOLVE_FUNCS / sizeof RESOLVE_FUNCS[0])

/* minimal libc.so whose .dynsym/.dynstr the protector parses itself */
static void build_fake_so(emu_t *e){
    size_t dstr_cap = 64;
    for(int i = 0; i < NRESOLVE; i++) dstr_cap += strlen(RESOLVE_FUNCS[i]) + 1;
    uint8_t *dynstr = (uint8_t *)calloc(1, dstr_cap);
    size_t dstr_len = 1;
    uint32_t name_off[NRESOLVE];
    for(int i = 0; i < NRESOLVE; i++){
        name_off[i] = (uint32_t)dstr_len;
        size_t l = strlen(RESOLVE_FUNCS[i]);
        memcpy(dynstr + dstr_len, RESOLVE_FUNCS[i], l);
        dstr_len += l + 1;
    }
    int nsym = NRESOLVE + 1;
    uint8_t *dynsym = (uint8_t *)calloc(24, (size_t)nsym);
    for(int i = 0; i < NRESOLVE; i++){
        uint8_t *s = dynsym + (size_t)(i+1)*24;
        uint32_t v = name_off[i];           memcpy(s, &v, 4);
        s[4] = 0x12;                        /* GLOBAL|FUNC */
        uint16_t shx = 0xfff1;              memcpy(s+6, &shx, 2);
        uint64_t val = stub_for(e, RESOLVE_FUNCS[i]) - LIBC_BASE;
        VLOG("    [fixture export] %s -> 0x%llx\n",RESOLVE_FUNCS[i],(unsigned long long)(val+LIBC_BASE));
        memcpy(s+8, &val, 8);
        uint64_t sz = 0x10;                 memcpy(s+16, &sz, 8);
    }
    const char *secnames[] = {"", ".shstrtab", ".dynsym", ".dynstr", ".text",
                              ".note.gnu.build-id", ".rodata", ".note.android.ident"};
    int shnum = 8;
    uint8_t *shstr = (uint8_t *)calloc(1, 256);
    size_t slen = 1; uint32_t sn_off[8]={0};
    for(int i = 1; i < shnum; i++){
        sn_off[i] = (uint32_t)slen;
        size_t l = strlen(secnames[i]);
        memcpy(shstr + slen, secnames[i], l); slen += l + 1;
    }
    size_t off = 64;
    size_t shstr_off = off; off += slen;
    size_t dynsym_off = off; off += 24*(size_t)nsym;
    size_t dynstr_off = off; off += dstr_len;
    size_t text_off = off; off += 0x100;
    size_t rodata_off = off; off += 0x20;
    size_t shoff = (off + 7) & ~(size_t)7;
    size_t note_off = shoff + (size_t)shnum*64;
    size_t total = note_off + 36;
    uint8_t *blob = (uint8_t *)calloc(1, total);
    memcpy(blob, "\x7f""ELF", 4);
    blob[4] = 2; blob[5] = 1; blob[6] = 1;
    uint16_t et = 3, mach = 0xB7, ehsize = 64, phentsize = 56, phnum = 0,
             shentsize = 64, shstrndx = 1;
    uint32_t ver = 1;
    uint64_t shv = shoff;
    memcpy(blob+16, &et, 2); memcpy(blob+18, &mach, 2); memcpy(blob+20, &ver, 4);
    memcpy(blob+40, &shv, 8);
    memcpy(blob+52, &ehsize, 2); memcpy(blob+54, &phentsize, 2);
    memcpy(blob+56, &phnum, 2); memcpy(blob+58, &shentsize, 2);
    memcpy(blob+60, &shnum, 2); memcpy(blob+62, &shstrndx, 2);
    memcpy(blob+shstr_off, shstr, slen);
    memcpy(blob+dynsym_off, dynsym, 24*(size_t)nsym);
    memcpy(blob+dynstr_off, dynstr, dstr_len);
    uint32_t ret = 0xd65f03c0; memcpy(blob+text_off, &ret, 4);
    for(int i = 0; i < shnum; i++){
        uint8_t *s = blob + shoff + (size_t)i*64;
        uint32_t nm = sn_off[i], ty = 0;
        if(i == 2) ty = 11; else if(i > 0) ty = (i==5||i==7) ? 7 : 3;
        if(i == 4 || i == 6) ty = 1;
        memcpy(s, &nm, 4); memcpy(s+4, &ty, 4);
        if(i == 1){ uint64_t o=shstr_off,l=slen,a=1; memcpy(s+24,&o,8); memcpy(s+32,&l,8); memcpy(s+48,&a,8); }
        else if(i == 2){ uint64_t o=dynsym_off,l=24*(size_t)nsym,a=8,es=24; uint32_t lk=3,in=1;
                         memcpy(s+24,&o,8); memcpy(s+32,&l,8); memcpy(s+40,&lk,4); memcpy(s+44,&in,4);
                         memcpy(s+48,&a,8); memcpy(s+56,&es,8); }
        else if(i == 3){ uint64_t o=dynstr_off,l=dstr_len,a=1; memcpy(s+24,&o,8); memcpy(s+32,&l,8); memcpy(s+48,&a,8); }
        else if(i == 4){ uint64_t o=text_off,l=0x100,a=4; memcpy(s+24,&o,8); memcpy(s+32,&l,8); memcpy(s+48,&a,8); }
        else if(i == 5){ uint64_t o=note_off,l=0x24,a=4; memcpy(s+24,&o,8); memcpy(s+32,&l,8); memcpy(s+48,&a,8); }
        else if(i == 6){ uint64_t o=rodata_off,l=0x20,a=4; memcpy(s+24,&o,8); memcpy(s+32,&l,8); memcpy(s+48,&a,8); }
        else if(i == 7){ uint64_t l=0x18,a=4; memcpy(s+32,&l,8); memcpy(s+48,&a,8); }
    }
    uint32_t n0=4, n1=20, n2=3;
    memcpy(blob+note_off, &n0, 4); memcpy(blob+note_off+4, &n1, 4); memcpy(blob+note_off+8, &n2, 4);
    memcpy(blob+note_off+12, "GNU", 4);
    for(int i = 0; i < 20; i++) blob[note_off+16+i] = (uint8_t)i;
    free(dynstr); free(dynsym); free(shstr);
    e->fake_so = blob; e->fake_so_len = total;
}

/* ------------------------------------------------------------------ */
/* mapping                                                             */

static int emu_map(emu_t *e){
    for(int i = 0; i < e->nsegs; i++){
        const seg_t *s = &e->segs[i];
        uint64_t base = (s->va+e->load_bias) & ~0xfffULL;
        uint64_t end  = (s->va+e->load_bias + s->memsz + 0xfff) & ~0xfffULL;
        uc_err rc = uc_mem_map(e->uc, base, end - base, UC_PROT_ALL);
        if(rc && rc != UC_ERR_MAP) return -1;
        if(s->filesz){
            size_t avail = e->raw_len > s->off ? e->raw_len - s->off : 0;
            size_t wr = s->filesz < avail ? (size_t)s->filesz : avail;
            if(wr) uc_mem_write(e->uc, s->va+e->load_bias, e->raw + s->off, wr);
        }
        if(s->memsz > s->filesz){
            size_t zl = (size_t)(s->memsz - s->filesz);
            uint8_t *z = (uint8_t *)calloc(1, zl);
            uc_mem_write(e->uc, s->va+e->load_bias + s->filesz, z, zl);
            free(z);
        }
    }
    uc_mem_map(e->uc, STACK_TOP - STACK_SIZE, STACK_SIZE, UC_PROT_ALL);
    uc_mem_map(e->uc, HEAP_BASE, HEAP_SIZE, UC_PROT_ALL);
    uc_mem_map(e->uc, TLS_BASE, TLS_SIZE, UC_PROT_ALL);
    uc_mem_map(e->uc, STUB_BASE, STUB_SIZE, UC_PROT_ALL);
    uc_mem_map(e->uc, MISC_BASE, MISC_SIZE, UC_PROT_ALL);
    uc_mem_map(e->uc, CTXSTACK_BASE, MAX_THREADS * CTXSTACK_SIZE, UC_PROT_ALL);
    uc_mem_map(e->uc, CTXTLS_BASE, MAX_THREADS * CTXTLS_SIZE, UC_PROT_ALL);
    return 0;
}

/* ------------------------------------------------------------------ */
/* heap + strings                                                      */

static uint64_t heap_alloc(emu_t *e, uint64_t size, int zero){
    if(!size) size = 1;
    uint64_t p = (e->heap_next + 0xf) & ~0xfULL;
    e->heap_next = p + size;
    if(e->nblocks < MAX_BLOCKS){
        e->blocks[e->nblocks].ptr = p;
        e->blocks[e->nblocks].size = size;
        e->nblocks++;
    }
    if(zero){
        size_t zl = size < (1u<<24) ? (size_t)size : (1u<<24);
        uint8_t *z = (uint8_t *)calloc(1, zl);
        uc_mem_write(e->uc, p, z, zl);
        free(z);
    }
    return p;
}

static uint64_t heap_realloc(emu_t *e, uint64_t ptr, uint64_t size){
    if(!ptr) return heap_alloc(e, size, 0);
    uint64_t old = 0;
    for(int i = 0; i < e->nblocks; i++)
        if(e->blocks[i].ptr == ptr){ old = e->blocks[i].size; break; }
    uint64_t np = heap_alloc(e, size, 0);
    if(old){
        uint64_t n = old < size ? old : size;
        uint8_t *tmp = (uint8_t *)malloc(n);
        uc_mem_read(e->uc, ptr, tmp, n);
        uc_mem_write(e->uc, np, tmp, n);
        free(tmp);
    }
    return np;
}

static int read_cstr(emu_t *e, uint64_t addr, char *out, size_t max){
    if(!addr) return 0;
    size_t n = 0;
    while(n + 64 < max){
        uint8_t chunk[64];
        if(uc_mem_read(e->uc, addr + n, chunk, 64)) break;
        for(int i = 0; i < 64; i++)
            if(!chunk[i]){ memcpy(out + n, chunk, (size_t)i); out[n+i] = 0; return (int)(n+i); }
        memcpy(out + n, chunk, 64);
        n += 64;
    }
    out[n] = 0;
    return (int)n;
}

static void write_cstr(emu_t *e, uint64_t addr, const char *s){
    uc_mem_write(e->uc, addr, s, strlen(s) + 1);
}

/* ------------------------------------------------------------------ */
/* registers                                                           */

static uint64_t rdreg(uc_engine *uc, int reg){
    uint64_t v = 0; uc_reg_read(uc, reg, &v); return v;
}
static void wrreg(uc_engine *uc, int reg, uint64_t v){ uc_reg_write(uc, reg, &v); }

#define R_X0   UC_ARM64_REG_X0
#define R_X1   UC_ARM64_REG_X1
#define R_X2   UC_ARM64_REG_X2
#define R_X30  UC_ARM64_REG_X30
#define R_X29  UC_ARM64_REG_X29
#define R_SP   UC_ARM64_REG_SP
#define R_PC   UC_ARM64_REG_PC

/* ------------------------------------------------------------------ */
/* minimal sscanf (maps parsing)                                       */

static int emu_sscanf(emu_t *e, uint64_t s_addr, uint64_t fmt_addr){
    uc_engine *uc = e->uc;
    static char s[1 << 16], fmt[1 << 16];
    read_cstr(e, s_addr, s, sizeof s);
    read_cstr(e, fmt_addr, fmt, sizeof fmt);
    uint64_t a[16];
    a[0] = rdreg(uc, UC_ARM64_REG_X2); a[1] = rdreg(uc, UC_ARM64_REG_X3);
    a[2] = rdreg(uc, UC_ARM64_REG_X4); a[3] = rdreg(uc, UC_ARM64_REG_X5);
    a[4] = rdreg(uc, UC_ARM64_REG_X6); a[5] = rdreg(uc, UC_ARM64_REG_X7);
    uint64_t sp = rdreg(uc, R_SP);
    for(int i = 6; i < 16; i++){
        uint64_t v = 0;
        uc_mem_read(uc, sp + (uint64_t)(i - 6) * 8, &v, 8);
        a[i] = v;
    }

    int nargs = 0, matches = 0;
    size_t si = 0, fi = 0;
    size_t sl = strlen(s), fl = strlen(fmt);
    while(fi < fl){
        char c = fmt[fi];
        if(c != '%'){
            /* literal: whitespace in fmt skips input whitespace; any other
             * literal must match the input (consume if it does) */
            if(c == ' ' || c == '\t'){
                while(si < sl && strchr(" \t\n\r", s[si])) si++;
            } else if(si < sl && s[si] == c){
                si++;
            } else break;
            fi++;
            continue;
        }
        fi++;
        int skip = 0;
        char lmod[8]; size_t lml = 0;
        if(fmt[fi] == '*'){ skip = 1; fi++; }
        size_t width=0;
        while(fi < fl && fmt[fi] >= '0' && fmt[fi] <= '9'){
            width=width<sizeof(s)?width*10+(size_t)(fmt[fi]-'0'):sizeof(s);fi++;
        }
        while(fi < fl && lml < 7 && strchr("hljztL", fmt[fi])) lmod[lml++] = fmt[fi++];
        lmod[lml] = 0;
        if(fi >= fl) break;
        char conv = fmt[fi]; fi++;
        if(conv == '%'){ if(si < sl && s[si] == '%') si++; continue; }
        while(si < sl && strchr(" \t\n\r", s[si])) si++;
        if(conv == 'n'){
            if(!skip && nargs < 16){
                int32_t v = (int32_t)si;
                uc_mem_write(uc, a[nargs], &v, 4);
                matches++; nargs++;
            }
            continue;
        }
        if(strchr("dixXuo", conv)){
            int base = (conv=='x'||conv=='X') ? 16 : conv=='o' ? 8 : conv=='i' ? 0 : 10;
            char tmp[sizeof s],*end;size_t length=sl-si;
            if(width&&length>width)length=width;
            memcpy(tmp,s+si,length);tmp[length]=0;
            unsigned long long val=strtoull(tmp,&end,base);
            if(end==tmp)break;
            si+=(size_t)(end-tmp);
            if(!skip && nargs < 16){
                if(lmod[0]=='h') { if(lmod[1]=='h'){uint8_t v=(uint8_t)val;uc_mem_write(uc,a[nargs],&v,1);}else{uint16_t v=(uint16_t)val;uc_mem_write(uc,a[nargs],&v,2);} }
                else if(lmod[0]){ uc_mem_write(uc, a[nargs], &val, 8); }
                else { int32_t v = (int32_t)val; uc_mem_write(uc, a[nargs], &v, 4); }
                matches++; nargs++;
            }
        } else if(conv == 's'){
            if(si >= sl) break;
            size_t start = si;
            while(si < sl && !strchr(" \t\n\r", s[si])) si++;
            if(!skip && nargs < 16){
                uc_mem_write(uc, a[nargs], s+start, si-start);
                uint8_t z = 0; uc_mem_write(uc, a[nargs] + (si-start), &z, 1);
                matches++; nargs++;
            }
        } else if(conv == 'c'){
            if(si >= sl) break;
            if(!skip && nargs < 16){
                uc_mem_write(uc, a[nargs], s+si, 1);
                matches++; nargs++;
            }
            si++;
        } else if(conv == 'p'){
            size_t start = si;
            if(si+1 < sl && s[si]=='0' && (s[si+1]=='x'||s[si+1]=='X')) si += 2;
            while(si < sl && strchr("0123456789abcdefABCDEF", s[si])) si++;
            if(si == start) break;
            if(!skip && nargs < 16){
                uint64_t val = strtoull(s+start, NULL, 16);
                uc_mem_write(uc, a[nargs], &val, 8);
                matches++; nargs++;
            }
        }
    }
    VLOG("    [guest sscanf] %.80s <- %.160s => %d\n",fmt,s,matches);
    return matches;
}

/* ------------------------------------------------------------------ */
/* import dispatch                                                     */

static int is_rnd_path(const char *p){
    return !strcmp(p, "/dev/urandom") || !strcmp(p, "/dev/random");
}
static size_t fill_rnd(uint8_t *dst, size_t n){
    for(size_t i = 0; i < n; i++) dst[i] = (uint8_t)(rand() >> 7);
    return n;
}

static fakefile_t *file_by_fp(emu_t *e, uint64_t fp){
    for(int i = 0; i < e->nfiles; i++)
        if(e->files[i].kind == 1 && MISC_BASE + 0x4000 + (uint64_t)i*0x100 == fp)
            return &e->files[i];
    return NULL;
}
static fakefile_t *file_by_fd(emu_t *e, uint64_t fd){
    for(int i = 0; i < e->nfiles; i++)
        if(e->files[i].kind == 2 && (uint64_t)e->files[i].fd == fd)
            return &e->files[i];
    return NULL;
}

static int64_t file_seek(fakefile_t *ff,int64_t offset,uint64_t whence){
    if(!ff)return -9;
    if(whence>2)return -22;
    uint64_t base=whence==1 ? ff->pos : whence==2 ? ff->len : 0;
    if(base>INT64_MAX || (offset>0 && base>(uint64_t)(INT64_MAX-offset)) ||
       (offset<0 && (uint64_t)(-(offset+1))+1>base))return -22;
    ff->pos=(size_t)((int64_t)base+offset);return (int64_t)ff->pos;
}

static int guest_fstat(emu_t *e,uint64_t fd,uint64_t addr){
    fakefile_t *ff=file_by_fd(e,fd);if(!ff)return -9;
    uint8_t buf[128]={0};uint32_t mode=0100644;uint64_t size=ff->len;
    memcpy(buf+16,&mode,4);memcpy(buf+48,&size,8);
    return uc_mem_write(e->uc,addr,buf,sizeof buf) ? -14 : 0;
}

static int guest_clock(emu_t *e,uint64_t addr,int realtime,int microseconds){
    /* A deterministic advancing clock lets guest deadline loops terminate. */
    e->clock_ns+=1000000;
    uint64_t ns=e->clock_ns;
    uint64_t stamp[2]={(realtime?1700000000ULL:1000000ULL)+ns/1000000000,
                       (ns%1000000000)/(microseconds?1000:1)};
    return uc_mem_write(e->uc,addr,stamp,sizeof stamp)?-14:0;
}

static int64_t guest_mmap(emu_t *e,uint64_t length,uint64_t flags,uint64_t fd,uint64_t offset){
    if(!length || length>0x10000000)return -22;
    fakefile_t *ff=NULL;
    if(!(flags&0x20)){ff=file_by_fd(e,fd);if(!ff)return -9;}
    uint64_t len=(length+0xfff)&~0xfffULL,p=e->mmap_next;
    if(uc_mem_map(e->uc,p,len,UC_PROT_ALL))return -12;
    e->mmap_next+=len;
    if(ff && offset<ff->len){
        size_t n=ff->len-(size_t)offset;if(n>length)n=(size_t)length;
        if(uc_mem_write(e->uc,p,ff->content+(size_t)offset,n))return -14;
    }
    return (int64_t)p;
}

static chan_t *chan_new(emu_t *e){
    if(e->nchans >= MAX_CHANS) return NULL;
    chan_t *c = &e->chans[e->nchans++];
    memset(c, 0, sizeof *c);
    c->used = 1;
    c->rfd = e->next_fd++;
    c->wfd = e->next_fd++;
    return c;
}
static chan_t *chan_by_rfd(emu_t *e, uint64_t fd){
    for(int i = 0; i < e->nchans; i++)
        if(e->chans[i].used && (uint64_t)e->chans[i].rfd == fd) return &e->chans[i];
    return NULL;
}
static chan_t *chan_by_wfd(emu_t *e, uint64_t fd){
    for(int i = 0; i < e->nchans; i++)
        if(e->chans[i].used && (uint64_t)e->chans[i].wfd == fd) return &e->chans[i];
    return NULL;
}
static void vlog_hex(const char *tag, uint64_t fd, const uint8_t *b, size_t n){
    if(!g_verbose) return;
    fprintf(stderr, "    %s fd=%llu %zu bytes:", tag, (unsigned long long)fd, n);
    for(size_t i = 0; i < n && i < 40; i++) fprintf(stderr, " %02x", b[i]);
    fprintf(stderr, "\n");
}
static size_t chan_write_guest(emu_t *e, chan_t *c, uint64_t buf, size_t n){
    uint8_t tmp[512];
    size_t room = sizeof c->buf - c->len, done = 0;
    if(n > room) n = room;
    while(done < n){
        size_t k = n - done > sizeof tmp ? sizeof tmp : n - done;
        uc_mem_read(e->uc, buf + done, tmp, k);
        memcpy(c->buf + c->len, tmp, k);
        c->len += k; done += k;
    }
    vlog_hex("[chan write]", (uint64_t)c->wfd, c->buf + (c->len > done ? c->len - done : c->len), done);
    return done;
}
static size_t chan_read_guest(emu_t *e, chan_t *c, uint64_t buf, size_t n){
    if(n > c->len) n = c->len;
    if(n && buf) uc_mem_write(e->uc, buf, c->buf, n);
    if(n) memmove(c->buf, c->buf + n, c->len - n);
    c->len -= n;
    return n;
}

/* ---- cooperative thread contexts ---- */
static uint32_t guest_pid(const emu_t *e){
    return e->cur_ctx && e->th[e->cur_ctx - 1].pid ?
           e->th[e->cur_ctx - 1].pid : 1234;
}
static uint32_t guest_ppid(const emu_t *e){
    return e->cur_ctx && e->th[e->cur_ctx - 1].ppid ?
           e->th[e->cur_ctx - 1].ppid : 500;
}

/* Forked processes must not clear or mutate their parent's data/BSS. Keep
 * independent copies of module data, the allocated heap, stack and TLS while
 * scheduling them in a single Unicorn engine. Kernel pipe state stays shared. */
static void fork_mem_free(region_t *mem, int count){
    if(!mem) return;
    for(int i = 0; i < count; i++) free(mem[i].data);
    free(mem);
}
static region_t *fork_mem_save(emu_t *e, int *count){
    region_t *mem = calloc((size_t)e->nsegs + (e->peer?(size_t)e->peer->nsegs:0) + 3, sizeof *mem);
    if(!mem) return NULL;
    int n = 0;
    for(const emu_t *m=e;m;m=m==e?e->peer:NULL){
    for(int i = 0; i < m->nsegs; i++){
        if(!(m->segs[i].flags & 2)) continue;      /* PF_W */
        mem[n].va = m->segs[i].va+m->load_bias;
        mem[n++].len = m->segs[i].memsz;
    }
    }
    mem[n].va = HEAP_BASE; mem[n++].len = e->heap_next - HEAP_BASE;
    mem[n].va = STACK_TOP - STACK_SIZE; mem[n++].len = STACK_SIZE;
    mem[n].va = TLS_BASE; mem[n++].len = TLS_SIZE;
    for(int i = 0; i < n; i++){
        mem[i].data = malloc(mem[i].len ? mem[i].len : 1);
        if(!mem[i].data || uc_mem_read(e->uc, mem[i].va, mem[i].data, mem[i].len)){
            fork_mem_free(mem, n);
            return NULL;
        }
    }
    *count = n;
    return mem;
}
static void fork_mem_restore(emu_t *e, const region_t *mem, int count){
    for(int i = 0; i < count; i++)
        uc_mem_write(e->uc, mem[i].va, mem[i].data, mem[i].len);
}

/* During a fork context's quantum the parent's writable memory lives in the
 * scheduler snapshot. Other mappings (including executable pages) stay mapped. */
static uc_err trace_memory(emu_t *e, uint64_t addr, void *buf, size_t len, int write){
    for(int i = 0; i < e->trace_mem_count; i++){
        region_t *r = &e->trace_mem[i];
        if(addr >= r->va && addr - r->va <= r->len && len <= r->len - (addr - r->va)){
            if(write) memcpy(r->data + (addr - r->va), buf, len);
            else memcpy(buf, r->data + (addr - r->va), len);
            return UC_ERR_OK;
        }
    }
    return write ? uc_mem_write(e->uc, addr, buf, len) : uc_mem_read(e->uc, addr, buf, len);
}

static int trace_reg_id(int i){
    return i < 29 ? UC_ARM64_REG_X0 + i : i == 29 ? R_X29 : i == 30 ? R_X30 :
           i == 31 ? R_SP : i == 32 ? R_PC : UC_ARM64_REG_PSTATE;
}

static int64_t trace_ptrace(emu_t *e, uint64_t request, uint64_t pid, uint64_t addr, uint64_t data){
    if(request == 16){                            /* PTRACE_ATTACH */
        if(pid != 1234) return -3;
        e->trace_pid = (uint32_t)pid;
        e->tracer_pid = guest_pid(e);
        e->trace_pending = e->trace_stopped = 1;
        e->trace_status = (19u << 8) | 0x7f;
        return 0;
    }
    if(!e->trace_pid || pid != e->trace_pid) return -3;
    switch(request){
    case 0x4200: return 0;                        /* SETOPTIONS */
    case 7:                                      /* CONT */
        e->trace_stopped = 0;
        return 0;
    case 17:                                     /* DETACH */
        e->trace_pid = 0;
        e->tracer_pid = 0;
        e->trace_stopped = e->trace_pending = 0;
        return 0;
    case 1: case 2: case 3: {                    /* PEEK{TEXT,DATA,USER} */
        uint64_t value = 0;
        if(trace_memory(e, addr, &value, sizeof value, 0)) return -5;
        return uc_mem_write(e->uc, data, &value, sizeof value) ? -14 : 0;
    }
    case 4: case 5: case 6:                      /* POKE{TEXT,DATA,USER} */
        return trace_memory(e, addr, &data, sizeof data, 1) ? -5 : 0;
    case 0x4204: case 0x4205: {                  /* GETREGSET / SETREGSET */
        uint64_t iov[2], regs[34] = {0};
        if(addr != 1 || !e->trace_cpu) return -5;  /* NT_PRSTATUS */
        if(uc_mem_read(e->uc, data, iov, sizeof iov)) return -14;
        size_t len = iov[1] < sizeof regs ? (size_t)iov[1] : sizeof regs;
        if(request == 0x4204){
            for(int i = 0; i < 34; i++)
                uc_context_reg_read(e->trace_cpu, trace_reg_id(i), &regs[i]);
            VLOG("    [trace regs] pc=0x%llx sp=0x%llx\n",
                 (unsigned long long)regs[32], (unsigned long long)regs[31]);
            if(uc_mem_write(e->uc, iov[0], regs, len)) return -14;
        } else {
            if(uc_mem_read(e->uc, iov[0], regs, len)) return -14;
            for(size_t i = 0; i < len / 8; i++)
                uc_context_reg_write(e->trace_cpu, trace_reg_id((int)i), &regs[i]);
        }
        iov[1] = len;
        return uc_mem_write(e->uc, data, iov, sizeof iov) ? -14 : 0;
    }
    case 0x4202: {                               /* GETSIGINFO */
        uint8_t info[128] = {0};
        uint32_t signo = (e->trace_status >> 8) & 0xff;
        memcpy(info, &signo, sizeof signo);
        return uc_mem_write(e->uc, data, info, sizeof info) ? -14 : 0;
    }
    default: return -5;
    }
}
static void ctx_save_regs(emu_t *e, uint64_t regs[31], uint64_t *sp, uint64_t *pc){
    for(int i = 0; i < 29; i++)
        uc_reg_read(e->uc, UC_ARM64_REG_X0 + i, &regs[i]);
    uc_reg_read(e->uc, UC_ARM64_REG_X29, &regs[29]);
    uc_reg_read(e->uc, UC_ARM64_REG_X30, &regs[30]);
    uc_reg_read(e->uc, UC_ARM64_REG_SP, sp);
    uc_reg_read(e->uc, UC_ARM64_REG_PC, pc);
}
static void ctx_load_regs(emu_t *e, const uint64_t regs[31], uint64_t sp, uint64_t pc){
    for(int i = 0; i < 29; i++)
        uc_reg_write(e->uc, UC_ARM64_REG_X0 + i, &regs[i]);
    uc_reg_write(e->uc, UC_ARM64_REG_X29, &regs[29]);
    uc_reg_write(e->uc, UC_ARM64_REG_X30, &regs[30]);
    uc_reg_write(e->uc, UC_ARM64_REG_SP, &sp);
    uc_reg_write(e->uc, UC_ARM64_REG_PC, &pc);
}

/* Give a forked/created context its own TLS copy so stack canaries of the
 * parent are not clobbered (real processes have per-thread TLS). */
static void ctx_private_tls(emu_t *e, thread_t *t, int idx){
    uint64_t tls = CTXTLS_BASE + (uint64_t)idx * CTXTLS_SIZE;
    uint8_t *tmp = (uint8_t *)malloc(TLS_SIZE);
    if(!tmp) return;
    if(!uc_mem_read(e->uc, TLS_BASE, tmp, TLS_SIZE))
        if(!uc_mem_write(e->uc, tls, tmp, TLS_SIZE))
            t->tls = tls;
    free(tmp);
}

/* run every runnable thread for one quantum; returns 1 if anything ran */
static int run_threads_once(emu_t *e){
    int progressed = 0;
    for(int i = 0; i < e->nth; i++){
        thread_t *t = &e->th[i];
        if(t->state == 2 && t->wait_pid && e->trace_pending) t->state = 1;
        if(t->state != 1) continue;
        uint64_t mregs[31], msp = 0, mpc = 0;
        region_t *parent_mem = NULL;
        int parent_count = 0;
        uint64_t parent_heap_next = e->heap_next;
        if(t->fork_mem){
            parent_mem = fork_mem_save(e, &parent_count);
            if(!parent_mem){ e->stop = 1; return progressed; }
            fork_mem_restore(e, t->fork_mem, t->nfork_mem);
            e->heap_next = t->fork_heap_next;
        }
        ctx_save_regs(e, mregs, &msp, &mpc);
        uc_context *main_cpu = NULL;
        if(uc_context_alloc(e->uc, &main_cpu) || uc_context_save(e->uc, main_cpu)){
            if(main_cpu) uc_context_free(main_cpu);
            if(parent_mem){
                fork_mem_restore(e, parent_mem, parent_count);
                fork_mem_free(parent_mem, parent_count);
                e->heap_next = parent_heap_next;
            }
            e->stop = 1;
            return progressed;
        }
        if(t->cpu) uc_context_restore(e->uc, t->cpu);
        else ctx_load_regs(e, t->regs, t->sp, t->pc);
        e->trace_cpu = main_cpu;
        e->trace_mem = parent_mem;
        e->trace_mem_count = parent_count;
        if(t->wait_pid && e->trace_pending){
            if(t->wait_status) uc_mem_write(e->uc, t->wait_status, &e->trace_status, 4);
            wrreg(e->uc, R_X0, e->trace_pid);
            e->trace_pending = 0;
            t->wait_pid = 0;
        }
        uint64_t prev_tls = 0;
        uc_reg_read(e->uc, UC_ARM64_REG_TPIDR_EL0, &prev_tls);
        if(t->tls) uc_reg_write(e->uc, UC_ARM64_REG_TPIDR_EL0, &t->tls);
        e->cur_ctx = i + 1;
        uc_err rc = uc_emu_start(e->uc, t->pc, 0, 0, THREAD_QUANTUM);
        if(t->tls) uc_reg_write(e->uc, UC_ARM64_REG_TPIDR_EL0, &prev_tls);
        e->cur_ctx = 0;
        uint64_t pc = 0;
        uc_reg_read(e->uc, UC_ARM64_REG_PC, &pc);
        int ended = (t->state == 3), blocked = (t->state == 2);
        ctx_save_regs(e, t->regs, &t->sp, &t->pc);
        if(!t->cpu) uc_context_alloc(e->uc, &t->cpu);
        if(!t->cpu || uc_context_save(e->uc, t->cpu)) e->stop = 1;
        if(parent_mem){
            fork_mem_free(t->fork_mem, t->nfork_mem);
            t->fork_mem = fork_mem_save(e, &t->nfork_mem);
            t->fork_heap_next = e->heap_next;
            if(!t->fork_mem) e->stop = 1;
            fork_mem_restore(e, parent_mem, parent_count);
            fork_mem_free(parent_mem, parent_count);
            e->heap_next = parent_heap_next;
        }
        if(pc == SENT_THREAD || ended) t->state = 3;
        else if(!blocked) t->state = (rc == UC_ERR_OK || rc == UC_ERR_FETCH_UNMAPPED) ? 1 : 3;
        uc_context_restore(e->uc, main_cpu);
        e->trace_cpu = NULL;
        e->trace_mem = NULL;
        e->trace_mem_count = 0;
        uc_context_free(main_cpu);
        progressed = 1;
    }
    return progressed;
}

/* resolve a virtual path to emulated file content (same policy as fopen) */
static const char *path_content(emu_t *e, const char *path, size_t *outlen){
    char *maps = NULL;
    if(e->apk && !strcmp(path,guest_game(e)->apk)){
        *outlen=e->apk_len;return (const char *)e->apk;
    }
    for(emu_t *m=e;m;m=m==e?e->peer:NULL){
        const char *name=m->image_name?m->image_name:"libsupercell_brawlstars.so";
        const char *last=strrchr(path,'/');last=last?last+1:path;
        if(!strcmp(last,name)){*outlen=m->raw_len;return (const char *)m->raw;}
    }
    if(!strcmp(path, "/proc/self/maps") || !strcmp(path, "/proc/1234/maps")){
        maps = build_maps(e, outlen);
        return maps;
    }
    if(!strcmp(path, "/proc/self/status") || !strcmp(path, "/proc/1234/status")){
        const char *marker=strstr(STATUS_CONTENT,"TracerPid:\t0");
        const char *state=strchr(STATUS_CONTENT,'\n');
        int n=snprintf(e->status_content,sizeof e->status_content,"Name:\torg.supercell.%.*s%.*sTracerPid:\t%u%s",
                       (int)strlen(guest_game(e)->comm)-1,guest_game(e)->comm,
                       (int)(marker-state),state,e->tracer_pid,marker+12);
        *outlen=(size_t)n;
        return e->status_content;
    }
    if(!strcmp(path,"/proc/self/task/1234/comm") || !strcmp(path,"/proc/1234/task/1234/comm")){
        *outlen=strlen(guest_game(e)->comm);return guest_game(e)->comm;
    }
    if(!strcmp(path,"/proc/self/task") || !strcmp(path,"/proc/1234/task")){
        *outlen=0;return "";
    }
    if(!strcmp(path,"/proc/self/cmdline")){
        *outlen=strlen(guest_game(e)->package)+1;return guest_game(e)->package;
    }
    if(!strcmp(path,"/proc/sys/kernel/yama/ptrace_scope")){*outlen=2;return "0\n";}
    const char *basename=strrchr(path,'/');basename=basename?basename+1:path;
    if(!strcmp(basename,"libc.so") || !strcmp(basename,"libdl.so") || !strcmp(basename,"liblog.so")){
        if(!e->fake_so) build_fake_so(e);
        *outlen = e->fake_so_len;
        return (const char *)e->fake_so;
    }
    *outlen = 0;
    return is_rnd_path(path)?"":NULL;
}

static uint64_t jni_first_arg(emu_t *e,uint64_t args,int va_list){
    uint64_t ptr=args,value=0;
    if(va_list){
        uint64_t stack=0,top=0;int32_t offset=0;
        if(uc_mem_read(e->uc,args,&stack,8) || uc_mem_read(e->uc,args+8,&top,8) ||
           uc_mem_read(e->uc,args+24,&offset,4)) return 0;
        ptr=offset<0 ? top+(int64_t)offset : stack;
    }
    uc_mem_read(e->uc,ptr,&value,8);return value;
}

/* AArch64 va_list has stack/gr_top/vr_top pointers and signed GR/VR offsets.
 * Work on a copy: formatting must not consume the caller's va_list. */
typedef struct {uint64_t stack,gr_top,vr_top;int32_t gr_offs,vr_offs;} guest_va_t;
static int guest_va_next(emu_t *e,guest_va_t *ap,uint64_t *value){
    uint64_t address;
    if(ap->gr_offs<0){address=ap->gr_top+(int64_t)ap->gr_offs;ap->gr_offs+=8;}
    else {address=ap->stack;ap->stack+=8;}
    return uc_mem_read(e->uc,address,value,8)?-1:0;
}
static int guest_vsnprintf(emu_t *e,uint64_t dst,uint64_t capacity,uint64_t format,uint64_t va){
    char fmt[4096],result[16384];guest_va_t ap;
    if(uc_mem_read(e->uc,va,&ap,sizeof ap))return -1;
    read_cstr(e,format,fmt,sizeof fmt);
    size_t used=0;
    for(size_t i=0;fmt[i];){
        if(used>=sizeof result-1)return -1;
        if(fmt[i]!='%'){result[used++]=fmt[i++];continue;}
        i++;
        if(fmt[i]=='%'){result[used++]='%';i++;continue;}
        char spec[64]="%",part[8192];size_t n=1;
        while(fmt[i]&&strchr("-+ #0.0123456789",fmt[i])){
            if(n>=sizeof spec-5)return -1;
            spec[n++]=fmt[i++];
        }
        int wide=0;
        while(fmt[i]&&strchr("hljzt",fmt[i])){if(fmt[i]!='h')wide=1;i++;}
        char conversion=fmt[i++];uint64_t value=0;int length;
        if(!conversion||guest_va_next(e,&ap,&value))return -1;
        if(strchr("diuoxX",conversion)){
            spec[n++]='l';spec[n++]='l';spec[n++]=conversion;spec[n]=0;
            if(conversion=='d'||conversion=='i')length=snprintf(part,sizeof part,spec,(long long)(wide?(int64_t)value:(int32_t)value));
            else length=snprintf(part,sizeof part,spec,(unsigned long long)(wide?value:(uint32_t)value));
        }else if(conversion=='s'){
            char text[8192];if(value)read_cstr(e,value,text,sizeof text);else strcpy(text,"(null)");
            spec[n++]='s';spec[n]=0;length=snprintf(part,sizeof part,spec,text);
        }else if(conversion=='c'){
            spec[n++]='c';spec[n]=0;length=snprintf(part,sizeof part,spec,(int)value);
        }else if(conversion=='p'){
            spec[n++]='p';spec[n]=0;length=snprintf(part,sizeof part,spec,(void *)(uintptr_t)value);
        }else {
            fprintf(stderr,"error: unsupported guest format conversion %c\n",conversion);return -1;
        }
        if(length<0||(size_t)length>=sizeof part||used+(size_t)length>=sizeof result)return -1;
        memcpy(result+used,part,(size_t)length);used+=(size_t)length;
    }
    result[used]=0;
    if(capacity){
        size_t copied=used<capacity-1?used:(size_t)capacity-1;
        if(uc_mem_write(e->uc,dst,result,copied)||uc_mem_write(e->uc,dst+copied,"",1))return -1;
    }
    VLOG("    [guest format] %s -> %s\n",fmt,result);
    return (int)used;
}

static int guest_stat_path(emu_t *e,uint64_t path_addr,uint64_t result){
    char path[512]="";read_cstr(e,path_addr,path,sizeof path);
    size_t len=0;uint32_t mode=0100644;
    if(!strcmp(path,guest_game(e)->apk) && e->apk)len=e->apk_len;
    else {
        const char *last=strrchr(path,'/');last=last?last+1:path;
        int found=0;
        for(emu_t *m=e;m;m=m==e?e->peer:NULL)
            if(!strcmp(last,m->image_name?m->image_name:"libsupercell_brawlstars.so")){len=m->raw_len;found=1;break;}
        if(!found){uint32_t error=2;uc_mem_write(e->uc,e->errno_addr,&error,4);return -2;}
    }
    uint8_t buf[128]={0};uint64_t size=len;
    memcpy(buf+16,&mode,4);memcpy(buf+48,&size,8);
    VLOG("    [stat] %s size=%zu\n",path,len);
    return uc_mem_write(e->uc,result,buf,sizeof buf)?-14:0;
}

static void dispatch_import(emu_t *e, const char *name){
    /* Bionic's 64-bit file APIs use the same argument ABI on AArch64. */
    if(!strcmp(name,"lseek64"))name="lseek";
    if(!strcmp(name,"fseeko")||!strcmp(name,"fseeko64"))name="fseek";
    if(!strcmp(name,"ftello")||!strcmp(name,"ftello64"))name="ftell";
    if(!strcmp(name,"open64"))name="open";
    if(!strcmp(name,"mmap64"))name="mmap";
    uc_engine *uc = e->uc;
    uint64_t lr = rdreg(uc, R_X30);
    uint64_t a0 = rdreg(uc, R_X0), a1 = rdreg(uc, R_X1), a2 = rdreg(uc, R_X2),
             a3 = rdreg(uc, UC_ARM64_REG_X3);
    (void)a3;
    if(g_verbose && (!strcmp(name,"vfprintf") || !strcmp(name,"android_set_abort_message"))){
        char message[512]="";read_cstr(e,!strcmp(name,"vfprintf")?a1:a0,message,sizeof message);
        VLOG("    [guest message] %s\n",message);
        if(!strcmp(name,"vfprintf")){
            uint64_t arg=jni_first_arg(e,a2,1);read_cstr(e,arg,message,sizeof message);
            VLOG("    [guest message arg] 0x%llx %s\n",(unsigned long long)arg,message);
        }
    }
    if(e->import_calls++<50000) VLOG("    [call] %-24s a0=0x%llx a1=0x%llx a2=0x%llx lr=0x%llx ctx=%d\n",
         name, (unsigned long long)a0, (unsigned long long)a1,
         (unsigned long long)a2, (unsigned long long)lr, e->cur_ctx);
    #define RET(v) do{ wrreg(uc, R_X0, (uint64_t)(v)); wrreg(uc, R_PC, lr); return; }while(0)
    #define RET0() RET(0)

    if(!strcmp(name,"emu_constructor_resume")){
        unsigned *depth=&e->constructor_depth[e->cur_ctx];
        if(!*depth){e->stop=1;uc_emu_stop(uc);return;}
        --*depth;uint64_t object=e->constructors[e->cur_ctx][*depth].object,
                          dest=e->constructors[e->cur_ctx][*depth].lr;
        wrreg(uc,R_X0,object);wrreg(uc,R_X30,dest);wrreg(uc,R_PC,dest);return;
    }

    if(!strcmp(name,"inflateInit2_") || !strcmp(name,"inflateInit_")){
        if((!strcmp(name,"inflateInit2_")?a3:a2)!=112) RET(Z_VERSION_ERROR);
        char version=0;
        if(uc_mem_read(uc,!strcmp(name,"inflateInit2_")?a2:a1,&version,1) || version!=ZLIB_VERSION[0]) RET(Z_VERSION_ERROR);
        for(int i=0;i<16;i++)if(e->inflaters[i].active && e->inflaters[i].guest==a0) RET(Z_STREAM_ERROR);
        for(int i=0;i<16;i++)if(!e->inflaters[i].active){
            inflate_call_t *z=&e->inflaters[i];memset(z,0,sizeof *z);
            int rc=inflateInit2(&z->stream,!strcmp(name,"inflateInit2_")?(int)a1:MAX_WBITS);
            if(rc!=Z_OK) RET(rc);
            z->guest=a0;z->active=1;
            uint64_t marker=1;
            if(uc_mem_write(uc,a0+56,&marker,8)){inflateEnd(&z->stream);z->active=0;RET(Z_STREAM_ERROR);}
            RET(Z_OK);
        }
        RET(Z_MEM_ERROR);
    }
    if(!strcmp(name,"inflate") || !strcmp(name,"inflateEnd")){
        inflate_call_t *z=NULL;
        for(int i=0;i<16;i++)if(e->inflaters[i].active && e->inflaters[i].guest==a0){z=&e->inflaters[i];break;}
        if(!z) RET(Z_STREAM_ERROR);
        if(!strcmp(name,"inflateEnd")){
            int rc=inflateEnd(&z->stream);z->active=0;
            uint64_t zero=0;uc_mem_write(uc,a0+56,&zero,8);RET(rc);
        }
        uint8_t guest[112];
        if(uc_mem_read(uc,a0,guest,sizeof guest)) RET(Z_STREAM_ERROR);
        uint64_t in=rd64(guest,0),out=rd64(guest,24);
        uint32_t nin=rd32(guest,8),nout=rd32(guest,32);
        if(nin>128u*1024*1024 || nout>128u*1024*1024) RET(Z_MEM_ERROR);
        uint8_t *input=malloc(nin?nin:1),*output=malloc(nout?nout:1);
        if(!input || !output){free(input);free(output);RET(Z_MEM_ERROR);}
        if(nin && uc_mem_read(uc,in,input,nin)){free(input);free(output);RET(Z_STREAM_ERROR);}
        z->stream.next_in=input;z->stream.avail_in=nin;z->stream.next_out=output;z->stream.avail_out=nout;
        int rc=inflate(&z->stream,(int)a1);
        uint32_t used=nin-z->stream.avail_in,produced=nout-z->stream.avail_out;
        uint64_t next_in=in+used,next_out=out+produced,total_in=z->stream.total_in,total_out=z->stream.total_out,
                 adler=z->stream.adler;
        uint32_t avail_in=z->stream.avail_in,avail_out=z->stream.avail_out,type=(uint32_t)z->stream.data_type;
        memcpy(guest,&next_in,8);memcpy(guest+8,&avail_in,4);memcpy(guest+16,&total_in,8);
        memcpy(guest+24,&next_out,8);memcpy(guest+32,&avail_out,4);memcpy(guest+40,&total_out,8);
        memset(guest+48,0,8);memcpy(guest+88,&type,4);memcpy(guest+96,&adler,8);
        if((produced && uc_mem_write(uc,out,output,produced)) || uc_mem_write(uc,a0,guest,sizeof guest))rc=Z_STREAM_ERROR;
        VLOG("    [inflate] consumed=%u produced=%u rc=%d\n",used,produced,rc);
        z->stream.next_in=NULL;z->stream.next_out=NULL;free(input);free(output);RET(rc);
    }

    if(!strcmp(name,"dl_iterate_phdr") || !strcmp(name,"emu_phdr_resume")){
        unsigned *depth=&e->phdr_depth[e->cur_ctx];
        if(!strcmp(name,"dl_iterate_phdr")){
            if(!a0 || *depth>=8) RET(-1);
            phdr_call_t *f=&e->phdr_calls[e->cur_ctx][(*depth)++];
            *f=(phdr_call_t){a0,a1,lr,0};
        }else{
            if(!*depth){e->stop=1;uc_emu_stop(uc);return;}
            if(a0){uint64_t dest=e->phdr_calls[e->cur_ctx][--*depth].lr;
                wrreg(uc,R_X30,dest);wrreg(uc,R_PC,dest);return;}
        }
        phdr_call_t *f=&e->phdr_calls[e->cur_ctx][*depth-1];
        const emu_t *image=f->next==0?e:f->next==1?e->peer:NULL;
        f->next++;
        if(!image){uint64_t dest=f->lr;--*depth;wrreg(uc,R_X30,dest);wrreg(uc,R_PC,dest);wrreg(uc,R_X0,0);return;}
        uint64_t info=heap_alloc(e,64,1),phoff=rd64(image->raw,32),phdr=0;
        unsigned phnum=(rd32(image->raw,54)>>16)&0xffff;
        for(int i=0;i<image->nsegs;i++){
            const seg_t *s=&image->segs[i];
            if(phoff>=s->off && phoff-s->off<s->filesz && (uint64_t)phnum*56<=s->filesz-(phoff-s->off)){
                phdr=image->load_bias+s->va+phoff-s->off;break;
            }
        }
        if(!phdr){fprintf(stderr,"error: unmapped program headers\n");e->stop=1;uc_emu_stop(uc);return;}
        const char *base=image->image_name?image->image_name:"libsupercell_brawlstars.so";
        char path[512];snprintf(path,sizeof path,"%s/%s",guest_game(e)->native,base);
        uint64_t path_addr=heap_alloc(e,strlen(path)+1,0);write_cstr(e,path_addr,path);
        uint64_t fields[8]={image->load_bias,path_addr,phdr,phnum,2,0,0,0};
        if(uc_mem_write(uc,info,fields,sizeof fields)){e->stop=1;uc_emu_stop(uc);return;}
        VLOG("    [dl_iterate_phdr] %s base=0x%llx phnum=%u\n",base,(unsigned long long)image->load_bias,phnum);
        wrreg(uc,R_X0,info);wrreg(uc,R_X1,64);wrreg(uc,R_X2,f->data);
        wrreg(uc,R_X30,stub_for(e,"emu_phdr_resume"));wrreg(uc,R_PC,f->callback);return;
    }

    if(!strcmp(name,"crc32") || !strcmp(name,"adler32")){
        uint8_t buf[16384];uLong value=(uLong)a0;
        if(!a1) RET(!strcmp(name,"crc32")?crc32(0,NULL,0):adler32(0,NULL,0));
        while(a2){
            size_t n=a2<sizeof buf?(size_t)a2:sizeof buf;
            if(uc_mem_read(uc,a1,buf,n)){e->stop=1;uc_emu_stop(uc);return;}
            value=!strcmp(name,"crc32")?crc32(value,buf,(uInt)n):adler32(value,buf,(uInt)n);
            a1+=n;a2-=n;
        }
        RET(value);
    }

    if(!strcmp(name,"jvm_GetEnv") || !strcmp(name,"jvm_AttachCurrentThread")){
        uint64_t env=JNI_ENV;
        if(!a1 || uc_mem_write(uc,a1,&env,8)) RET(-1);
        RET0();
    }
    if(!strcmp(name,"jvm_DetachCurrentThread")) RET0();
    if(!strncmp(name,"jni_",4)){
        unsigned index=(unsigned)strtoul(name+4,NULL,10);
        VLOG("    [JNI] slot=%u x1=0x%llx x2=0x%llx\n",index,
             (unsigned long long)a1,(unsigned long long)a2);
        if(index==4) RET(0x10006);
        if(index==15 || index==228) RET0();
        if(index==17 || index==22 || index==23 || index==170) RET0();
        if(index==21 || index==25) RET(a1);
        if(index==29 || index==30){
            char type[128]="";read_cstr(e,a1,type,sizeof type);
            if(!strcmp(type,"java/io/File")) RET(jni_first_arg(e,a3,index==29));
            /* 69.414 listener constructor is only Object.<init>; no Java work
             * is hidden here. Its registrar is a separate class initializer. */
            if(!strcmp(type,"elsm/ar")){
                uint64_t p=heap_alloc(e,strlen(type)+1,0);write_cstr(e,p,type);RET(p);
            }
            if(!strcmp(type,"elsm/a")){
                /* This APK's no-arg constructor delegates to native b()V. */
                for(unsigned i=0;i<e->nnatives;i++)if(!strcmp(e->natives[i].owner,type) &&
                   !strcmp(e->natives[i].name,"b") && !strcmp(e->natives[i].signature,"()V")){
                    unsigned *depth=&e->constructor_depth[e->cur_ctx];if(*depth>=8)break;
                    uint64_t object=heap_alloc(e,strlen(type)+1,0);write_cstr(e,object,type);
                    e->constructors[e->cur_ctx][*depth].object=object;e->constructors[e->cur_ctx][(*depth)++].lr=lr;
                    wrreg(uc,R_X1,object);wrreg(uc,R_X30,stub_for(e,"emu_constructor_resume"));
                    wrreg(uc,R_PC,e->natives[i].function);return;
                }
            }
        }
        if(index==31){
            uint64_t p=heap_alloc(e,17,0);write_cstr(e,p,"java/lang/Class");RET(p);
        }
        if(index==144){
            char owner[256]="",field[128]="",signature[128]="";
            read_cstr(e,a1,owner,sizeof owner);read_cstr(e,a2,field,sizeof field);read_cstr(e,a3,signature,sizeof signature);
            for(unsigned i=0;i<e->nstatic_fields;i++)
                if(!strcmp(e->static_fields[i].owner,owner) && !strcmp(e->static_fields[i].name,field) &&
                   !strcmp(e->static_fields[i].signature,signature)) RET(e->static_fields[i].id);
            if(e->nstatic_fields>=128){e->stop=1;uc_emu_stop(uc);return;}
            unsigned i=e->nstatic_fields++;
            snprintf(e->static_fields[i].owner,sizeof e->static_fields[i].owner,"%s",owner);
            snprintf(e->static_fields[i].name,sizeof e->static_fields[i].name,"%s",field);
            snprintf(e->static_fields[i].signature,sizeof e->static_fields[i].signature,"%s",signature);
            uint64_t id=heap_alloc(e,strlen(field)+1,0);write_cstr(e,id,field);e->static_fields[i].id=id;
            if(!strcmp(owner,"android/os/Build$VERSION") && !strcmp(field,"SDK_INT") && !strcmp(signature,"I"))
                e->static_fields[i].value=30; /* same Android 11 profile as system properties */
            VLOG("    [JNI static field] %s.%s %s\n",owner,field,signature);RET(id);
        }
        if((index>=145 && index<=151) || (index>=154 && index<=160)){
            for(unsigned i=0;i<e->nstatic_fields;i++)if(e->static_fields[i].id==a2){
                if(index>=154){e->static_fields[i].value=a3;RET0();}
                RET(e->static_fields[i].value);
            }
        }
        if(index==6 || index==33 || index==113 || index==94 || index==167){
            char text[256]="";read_cstr(e,index==6 || index==167?a1:a2,text,sizeof text);
            VLOG("    [JNI name] %s\n",text);
            uint64_t p=heap_alloc(e,strlen(text)+1,0);write_cstr(e,p,text);RET(p);
        }
        if(index==169){ if(a2){uint8_t copy=0;uc_mem_write(uc,a2,&copy,1);} RET(a1); }
        if(index==168){char text[4096]="";read_cstr(e,a1,text,sizeof text);RET(strlen(text));}
        if(index==141 || index==142 || index==143){
            char method[128]="",owner[256]="";read_cstr(e,a1,owner,sizeof owner);
            read_cstr(e,a2,method,sizeof method);
            VLOG("    [JNI static void method] %s.%s\n",owner,method);
            /* Process.setArgV0 only renames this offline process. Do not
             * silently swallow Java failure reporters or native callbacks. */
            if(!strcmp(owner,"android/os/Process")&&!strcmp(method,"setArgV0")) RET0();
            fprintf(stderr,"error: unsupported JNI static-void call %s.%s\n",owner,method);
            if(g_verbose){
                uint64_t argument=index==141?a3:jni_first_arg(e,a3,index==142);
                char value[128]="";read_cstr(e,argument,value,sizeof value);
                VLOG("    [JNI static-void first argument] %s\n",value);
                uint64_t fp=rdreg(uc,R_X29),frame[2];
                for(unsigned i=0;i<16&&fp;i++){
                    if(uc_mem_read(uc,fp,frame,sizeof frame))break;
                    VLOG("    [JNI failure frame] 0x%llx\n",(unsigned long long)frame[1]);
                    if(frame[0]<=fp)break;
                    fp=frame[0];
                }
            }
            e->stop=1;uc_emu_stop(uc);return;
        }
        if(index==62 || index==63){
            char method[128]="";read_cstr(e,a2,method,sizeof method);
            if(!strcmp(method,"registerActivityLifecycleCallbacks")){
                e->lifecycle_listener=jni_first_arg(e,a3,index==62);RET0();
            }
        }
        if(index==115 || index==116){
            char method[128]="";read_cstr(e,a2,method,sizeof method);
            if(!strcmp(method,"currentActivityThread")){
                uint64_t p=heap_alloc(e,32,0);write_cstr(e,p,"android/app/ActivityThread");RET(p);
            }
        }
        if(index==118 || index==119){
            char owner[256]="",method[128]="";read_cstr(e,a1,owner,sizeof owner);read_cstr(e,a2,method,sizeof method);
            if(!strcmp(owner,"android/os/Debug") && (!strcmp(method,"isDebuggerConnected") || !strcmp(method,"waitingForDebugger"))) RET0();
        }
        if(index==34 || index==35 || index==36){
            char method[128]="";read_cstr(e,a2,method,sizeof method);
            const char *value=NULL;
            if(!strcmp(method,"getSystemContext")) value="android/app/ContextImpl";
            if(!strcmp(method,"getPackageManager")) value="android/app/ApplicationPackageManager";
            if(!strcmp(method,"getApplicationInfo")) value="android/content/pm/ApplicationInfo";
            if(!strcmp(method,"getPackageInfo")) value="android/content/pm/PackageInfo";
            if(!strcmp(method,"getPackageName")) value=guest_game(e)->package;
            if(!strcmp(method,"getClassLoader")) value="java/lang/ClassLoader";
            if(!strcmp(method,"getAssets")) value="android/content/res/AssetManager";
            if(!strcmp(method,"getFilesDir")) value=guest_game(e)->files;
            if(!strcmp(method,"getCacheDir")) value=guest_game(e)->cache;
            if(!strcmp(method,"getSystemService")){
                uint64_t argument=index==34?a3:jni_first_arg(e,a3,index==35);
                char service[128]="";read_cstr(e,argument,service,sizeof service);
                VLOG("    [JNI system service] %s\n",service);
                if(!strcmp(service,"accessibility")) value="android/view/accessibility/AccessibilityManager";
            }
            if(!strcmp(method,"getEnabledAccessibilityServiceList")) value="java/util/Collections$EmptyList";
            if(!strcmp(method,"getApplicationContext")) RET(a1);
            if(!strcmp(method,"getAbsolutePath") || !strcmp(method,"getPath") || !strcmp(method,"toString") || !strcmp(method,"intern")) RET(a1);
            if(!strcmp(method,"getName")){
                char path[512]="";read_cstr(e,a1,path,sizeof path);
                char *last=strrchr(path,'/');last=last?last+1:path;
                uint64_t p=heap_alloc(e,strlen(last)+1,0);write_cstr(e,p,last);RET(p);
            }
            if(!strcmp(method,"listFiles")){
                char path[512]="";read_cstr(e,a1,path,sizeof path);
                if(strcmp(path,guest_game(e)->native)) RET0();
                uint64_t array=heap_alloc(e,24,1),count=0;
                for(emu_t *m=e;m;m=m==e?e->peer:NULL){
                    char full[1024];
                    if(snprintf(full,sizeof full,"%s/%s",path,m->image_name?m->image_name:"libsupercell_brawlstars.so")>=(int)sizeof full){e->stop=1;uc_emu_stop(uc);return;}
                    uint64_t p=heap_alloc(e,strlen(full)+1,0);write_cstr(e,p,full);
                    uc_mem_write(uc,array+8+count++*8,&p,8);
                }
                uc_mem_write(uc,array,&count,8);RET(array);
            }
            if(value){uint64_t p=heap_alloc(e,strlen(value)+1,0);write_cstr(e,p,value);RET(p);}
        }
        if(index==38 || index==39){
            char method[128]="",path[512]="";
            read_cstr(e,a2,method,sizeof method);read_cstr(e,a1,path,sizeof path);
            if(!strcmp(method,"exists")) RET(guest_stat_path(e,a1,MISC_BASE+0x804000)==0);
            if(!strcmp(method,"isEnabled") && !strcmp(path,"android/view/accessibility/AccessibilityManager")) RET0();
            if(!strcmp(method,"addAccessibilityStateChangeListener") && !strcmp(path,"android/view/accessibility/AccessibilityManager")){
                e->accessibility_listener=jni_first_arg(e,a3,index==38);RET(e->accessibility_listener!=0);
            }
            if(!strcmp(method,"isEmpty") && !strcmp(path,"java/util/Collections$EmptyList")) RET(1);
            if(!strcmp(method,"hasSystemFeature") && !strcmp(path,"android/app/ApplicationPackageManager")){
                uint64_t arg=jni_first_arg(e,a3,index==38);char feature[256]="";read_cstr(e,arg,feature,sizeof feature);
                VLOG("    [JNI feature] %s\n",feature);
                if(!strncmp(feature,"org.chromium.",13)) RET0(); /* Pixel 5 has no ChromeOS ARC/Bertha features */
            }
        }
        if(index==95){
            char field[128]="";read_cstr(e,a2,field,sizeof field);
            if(!strcmp(field,"services")){
                uint64_t n=e->package.nservices;
                if(!n) RET0();
                uint64_t array=heap_alloc(e,8+n*8,1);uc_mem_write(uc,array,&n,8);
                for(unsigned i=0;i<n;i++){
                    const char *name=e->package.services[i].name;
                    uint64_t item=heap_alloc(e,strlen(name)+1,0);write_cstr(e,item,name);
                    uc_mem_write(uc,array+8+(uint64_t)i*8,&item,8);
                }
                RET(array);
            }
            if(!strcmp(field,"splitSourceDirs")) RET0(); /* base-only APK fixture */
            const char *value=NULL;
            if(!strcmp(field,"sourceDir") || !strcmp(field,"publicSourceDir")) value=guest_game(e)->apk;
            if(!strcmp(field,"dataDir")) value=guest_game(e)->data;
            if(!strcmp(field,"nativeLibraryDir")) value=guest_game(e)->native;
            if(!strcmp(field,"packageName")) value=guest_game(e)->package;
            if(!strcmp(field,"versionName") && *e->package.version) value=e->package.version;
            if(!strcmp(field,"name") || !strcmp(field,"permission")){
                char object[256]="";read_cstr(e,a1,object,sizeof object);
                for(unsigned i=0;i<e->package.nservices;i++)if(!strcmp(object,e->package.services[i].name)){
                    value=!strcmp(field,"name")?e->package.services[i].name:e->package.services[i].permission;
                    if(!*value) RET0();
                    break;
                }
            }
            if(value){uint64_t p=heap_alloc(e,strlen(value)+1,0);write_cstr(e,p,value);RET(p);}
        }
        if(index==100 || index==101){
            char field[128]="";read_cstr(e,a2,field,sizeof field);
            if(!strcmp(field,"versionCode")) RET(e->package.version_code);
        }
        if(index==101 || index==110){
            char field[128]="";read_cstr(e,a2,field,sizeof field);
            unsigned i;
            for(i=0;i<e->nobject_fields;i++)if(e->object_fields[i].object==a1 && !strcmp(e->object_fields[i].field,field))break;
            if(i==e->nobject_fields){
                if(index==101) RET0();
                if(i>=128){e->stop=1;uc_emu_stop(uc);return;}
                e->nobject_fields++;e->object_fields[i].object=a1;
                snprintf(e->object_fields[i].field,sizeof e->object_fields[i].field,"%s",field);
            }
            if(index==110){e->object_fields[i].value=a3;RET0();}
            RET(e->object_fields[i].value);
        }
        if(index==171){uint64_t n=0;uc_mem_read(uc,a1,&n,8);RET(n);}
        if(index==173){uint64_t n=0,p=0;uc_mem_read(uc,a1,&n,8);
            if(a2>=n) RET0();uc_mem_read(uc,a1+8+a2*8,&p,8);RET(p);}
        if(index==215){
            char owner[256]="";read_cstr(e,a1,owner,sizeof owner);
            if(a3>256-e->nnatives) RET(-1);
            for(uint64_t k=0;k<a3;k++){
                uint64_t record[3]={0};
                if(uc_mem_read(uc,a2+k*24,record,sizeof record)) RET(-1);
                unsigned i=e->nnatives++;
                snprintf(e->natives[i].owner,sizeof e->natives[i].owner,"%s",owner);
                read_cstr(e,record[0],e->natives[i].name,sizeof e->natives[i].name);
                read_cstr(e,record[1],e->natives[i].signature,sizeof e->natives[i].signature);
                e->natives[i].function=record[2];
                VLOG("    [JNI RegisterNatives] %s.%s%s = 0x%llx\n",owner,e->natives[i].name,
                     e->natives[i].signature,(unsigned long long)record[2]);
            }
            RET0();
        }
        fprintf(stderr,"error: unsupported JNI slot %u\n",index);
        e->stop=1;uc_emu_stop(uc);return;
    }

    if(!strcmp(name, "malloc"))                    RET(heap_alloc(e, a0, 0));
    if(!strcmp(name, "calloc"))                    RET(heap_alloc(e, a0*a1, 1));
    if(!strcmp(name, "realloc"))                   RET(heap_realloc(e, a0, a1));
    if(!strcmp(name, "free"))                      RET0();
    if(!strcmp(name, "posix_memalign")){
        uint64_t p = heap_alloc(e, a1, 0);
        uc_mem_write(uc, a0, &p, 8); RET0();
    }
    if(!strcmp(name, "memcpy") || !strcmp(name, "memmove") ||
       !strcmp(name, "__memcpy_chk") || !strcmp(name, "__memmove_chk") ||
       !strcmp(name, "__strncpy_chk")){
        if(a2 && a2 < (1u<<26)){
            uint8_t *tmp = (uint8_t *)malloc(a2);
            if(a1) uc_mem_read(uc, a1, tmp, a2); else memset(tmp, 0, a2);
            uc_mem_write(uc, a0, tmp, a2);
            free(tmp);
        }
        RET(a0);
    }
    if(!strcmp(name, "memset")){
        if(a2 && a2 < (1u<<26)){
            uint8_t *tmp = (uint8_t *)malloc(a2);
            memset(tmp, (int)(a1 & 0xff), a2);
            uc_mem_write(uc, a0, tmp, a2);
            free(tmp);
        }
        RET(a0);
    }
    if(!strcmp(name, "__errno"))                   RET(e->errno_addr);
    if(!strcmp(name, "memcmp")){
        if(a2 && a2 < (1u<<24)){
            uint8_t *x = (uint8_t *)malloc(a2), *y = (uint8_t *)malloc(a2);
            uc_mem_read(uc, a0, x, a2); uc_mem_read(uc, a1, y, a2);
            int r = memcmp(x, y, a2);
            free(x); free(y);
            RET((uint64_t)(r > 0 ? 1 : r < 0 ? -1 : 0));
        }
        RET0();
    }
    if(!strcmp(name, "memchr"))                    RET0();
    if(!strcmp(name, "mmap") || !strcmp(name, "mmap64")){
        RET(guest_mmap(e,a1,a3,rdreg(uc,UC_ARM64_REG_X4),rdreg(uc,UC_ARM64_REG_X5)));
    }
    if(!strcmp(name, "mprotect")){
        VLOG("    [mprotect] 0x%llx len=0x%llx prot=%llx\n",
             (unsigned long long)a0, (unsigned long long)a1, (unsigned long long)a2);
        RET0();
    }
    if(!strcmp(name, "munmap") || !strcmp(name, "madvise")) RET0();
    if(!strcmp(name, "mremap"))                    RET(heap_alloc(e, a1, 0));
    if(!strcmp(name, "getrandom") || !strcmp(name, "getentropy")){
        if(a0 && a1 && a1 < (1u<<20)){
            uint8_t *tmp = (uint8_t *)malloc(a1);
            for(uint64_t i = 0; i < a1; i++) tmp[i] = (uint8_t)(rand() >> 8);
            uc_mem_write(uc, a0, tmp, a1);
            free(tmp);
        }
        RET(a1);
    }
    if(!strcmp(name, "syscall")){
        VLOG("    [libc syscall] nr=%llu a1=0x%llx a2=0x%llx a3=0x%llx\n",
             (unsigned long long)a0, (unsigned long long)a1,
             (unsigned long long)a2, (unsigned long long)a3);
        if(a0 == 178) RET(1234);                   /* gettid */
        RET0();
    }
    if(!strcmp(name, "getenv"))                    RET0();
    if(!strcmp(name, "getpid"))                    RET(guest_pid(e));
    if(!strcmp(name, "getppid"))                   RET(guest_ppid(e));
    if(!strcmp(name, "getpagesize"))               RET(0x1000);
    if(!strcmp(name, "sysconf"))                   RET(a0 == 39 || a0 == 30 ? 0x1000 : 0);
    if(!strcmp(name, "getauxval"))                 RET0();
    if(!strcmp(name,"getuid") || !strcmp(name,"geteuid") ||
       !strcmp(name,"getgid") || !strcmp(name,"getegid")) RET(10123);
    if(!strcmp(name, "time"))                      RET((uint64_t)time(NULL));
    if(!strcmp(name, "clock"))                     RET0();
    if(!strcmp(name, "clock_gettime")){
        RET(guest_clock(e,a1,a0==0,0));
    }
    if(!strcmp(name, "gettimeofday")){
        if(a0) RET(guest_clock(e,a0,1,1));
        RET0();
    }
    if(!strcmp(name, "arc4random_buf")){
        if(a0 && a1 && a1 < (1u<<20)){
            uint8_t *tmp = (uint8_t *)malloc(a1);
            for(uint64_t i = 0; i < a1; i++) tmp[i] = (uint8_t)(rand() >> 8);
            uc_mem_write(uc, a0, tmp, a1);
            free(tmp);
        }
        RET0();
    }
    if(!strcmp(name, "arc4random_uniform") || !strcmp(name, "arc4random")) RET(0);
    if(!strcmp(name, "dlopen"))                    RET(0x1111);
    if(!strcmp(name, "dlsym")){
        char nm[128] = "";
        if(a1) read_cstr(e, a1, nm, sizeof nm);
        if(nm[0]){
            uint64_t ex = stub_for(e, nm);
            VLOG("    [dlsym] '%s' -> 0x%llx\n", nm, (unsigned long long)ex);
            RET(ex);
        }
        RET0();
    }
    if(!strcmp(name, "__stack_chk_fail")){
        VLOG("!!! __stack_chk_fail @LR=0x%llx\n", (unsigned long long)lr);
        e->stop = 1;
        uc_emu_stop(uc);
        RET0();
    }
    if(!strcmp(name, "abort")){
        fprintf(stderr,"error: guest abort at LR=0x%llx FP=0x%llx\n",
                (unsigned long long)lr,(unsigned long long)rdreg(uc,R_X29));
        if(g_verbose){
            uint64_t fp=rdreg(uc,R_X29),frame[2];
            for(unsigned i=0;i<12&&fp;i++){
                if(uc_mem_read(uc,fp,frame,sizeof frame))break;
                fprintf(stderr,"    [abort frame] 0x%llx\n",(unsigned long long)frame[1]);
                if(frame[0]<=fp)break;
                fp=frame[0];
            }
        }
        e->stop = 1;
        uc_emu_stop(uc);
        RET0();
    }
    if(!strcmp(name, "exit") || !strcmp(name, "_exit")){
        VLOG("    [exit] code=%llu LR=0x%llx\n", (unsigned long long)a0, (unsigned long long)lr);
        e->stop = 1;
        uc_emu_stop(uc);
        RET0();
    }
    if(!strcmp(name, "__cxa_atexit") || !strcmp(name, "__cxa_finalize") ||
       !strcmp(name, "android_set_abort_message")) RET0();
    if(!strcmp(name, "pthread_self"))              RET(0x12345+(uint64_t)e->cur_ctx);
    if(!strcmp(name, "pthread_equal"))             RET(a0==a1);
    if(!strcmp(name,"pthread_key_create")){
        if(e->next_key>=128) RET(11);
        uint32_t key=e->next_key++;
        if(uc_mem_write(uc,a0,&key,4)) RET(22);
        RET0();
    }
    if(!strcmp(name,"pthread_setspecific")){
        if(a0>=e->next_key) RET(22);
        e->thread_values[e->cur_ctx][a0]=a1;RET0();
    }
    if(!strcmp(name,"pthread_getspecific")) RET(a0<e->next_key?e->thread_values[e->cur_ctx][a0]:0);
    if(!strcmp(name,"pthread_key_delete")){
        if(a0>=e->next_key) RET(22);
        for(int i=0;i<=MAX_THREADS;i++)e->thread_values[i][a0]=0;
        RET0();
    }
    if(!strcmp(name, "pthread_create")){
        VLOG("    [pthread_create] routine=0x%llx arg=0x%llx\n",
             (unsigned long long)a2, (unsigned long long)a3);
        if(e->nth < MAX_THREADS){
            int i = e->nth++;
            thread_t *t = &e->th[i];
            memset(t, 0, sizeof *t);
            t->state = 1;
            t->pid = guest_pid(e);
            t->ppid = guest_ppid(e);
            t->regs[0] = a3;                       /* start routine argument */
            t->regs[30] = SENT_THREAD;             /* thread exit sentinel */
            t->sp = STACK_TOP - 0x800000 - (uint64_t)i * 0x100000;
            t->regs[29] = t->sp;
            t->pc = a2;
            ctx_private_tls(e, t, i);
            if(a0){ uint64_t hv = (uint64_t)(i + 1); uc_mem_write(uc, a0, &hv, 8); }
        }
        RET0();
    }
    if(!strcmp(name,"pthread_cond_wait") || !strcmp(name,"pthread_cond_timedwait")){
        if(!e->cur_ctx && e->nth){
            e->yield_workers=1;
            uc_emu_stop(uc);
        }
        RET0();
    }
    if(!strncmp(name, "pthread_", 8) || !strncmp(name, "sched_", 6)) RET0();
    if(!strcmp(name, "strcmp")){
        static char s1[1024], s2[1024];
        read_cstr(e, a0, s1, sizeof s1);
        read_cstr(e, a1, s2, sizeof s2);
        int r = strcmp(s1, s2);
        RET((uint64_t)(r > 0 ? 1 : r < 0 ? -1 : 0));
    }
    if(!strcmp(name,"strncmp") || !strcmp(name,"strcasecmp")){
        char left[8192],right[8192];read_cstr(e,a0,left,sizeof left);read_cstr(e,a1,right,sizeof right);
        if(!strcmp(name,"strncmp"))RET((uint64_t)(int64_t)strncmp(left,right,(size_t)a2));
        size_t i=0;
        for(;;i++){
            unsigned char l=(unsigned char)left[i],r=(unsigned char)right[i];
            if(l>='A'&&l<='Z')l+='a'-'A';
            if(r>='A'&&r<='Z')r+='a'-'A';
            if(l!=r||!l)RET((uint64_t)(int64_t)((int)l-(int)r));
        }
    }
    if(!strcmp(name, "strlen")){
        static char sb[4096];
        RET((uint64_t)read_cstr(e, a0, sb, sizeof sb));
    }
    if(!strcmp(name, "strcpy")){
        static char sb[4096];
        read_cstr(e, a1, sb, sizeof sb);
        write_cstr(e, a0, sb);
        RET(a0);
    }
    if(!strcmp(name, "strcat"))                    RET(a0);
    if(!strcmp(name, "strchr")){
        static char sb[4096];
        read_cstr(e, a0, sb, sizeof sb);
        char *p = strchr(sb, (int)(a1 & 0xff));
        RET(p ? a0 + (uint64_t)(p - sb) : 0);
    }
    if(!strcmp(name, "strstr")){
        static char hay[8192], needle[512];
        read_cstr(e, a0, hay, sizeof hay);
        read_cstr(e, a1, needle, sizeof needle);
        char *p = needle[0] ? strstr(hay, needle) : hay;
        RET(p ? a0 + (uint64_t)(p - hay) : 0);
    }
    if(!strcmp(name, "atoi")){
        static char sb[256];
        read_cstr(e, a0, sb, sizeof sb);
        RET((uint64_t)(long long)atoi(sb));
    }
    if(!strcmp(name, "strtol")){
        static char sb[512];
        read_cstr(e, a0, sb, sizeof sb);
        RET((uint64_t)strtoll(sb, NULL, 0));
    }
    if(!strncmp(name, "strtou", 6) || !strncmp(name, "strtod", 6) ||
       !strncmp(name, "strtof", 6) || !strcmp(name, "strtol_l")){
        static char sb[512];
        read_cstr(e, a0, sb, sizeof sb);
        RET((uint64_t)strtoull(sb, NULL, 0));
    }
    if(!strcmp(name,"__vsnprintf_chk") || !strcmp(name,"vsnprintf")){
        int checked=!strcmp(name,"__vsnprintf_chk");
        if(checked&&a1>a3){fprintf(stderr,"error: guest formatting buffer overflow\n");e->stop=1;uc_emu_stop(uc);return;}
        uint64_t format=checked?rdreg(uc,UC_ARM64_REG_X4):a2;
        uint64_t va=checked?rdreg(uc,UC_ARM64_REG_X5):a3;
        int length=guest_vsnprintf(e,a0,a1,format,va);
        if(length<0){e->stop=1;uc_emu_stop(uc);return;}
        RET((uint64_t)length);
    }
    if(!strcmp(name,"snprintf") || !strcmp(name,"__snprintf_chk")){
        int checked=!strcmp(name,"__snprintf_chk");
        if(checked&&a1>a3){e->stop=1;uc_emu_stop(uc);return;}
        unsigned first=checked?5:3;
        uint64_t storage=MISC_BASE+0x805000,registers[8]={0};
        for(unsigned i=first;i<8;i++)registers[i-first]=rdreg(uc,UC_ARM64_REG_X0+i);
        guest_va_t ap={0};ap.stack=rdreg(uc,R_SP);
        ap.gr_top=storage+64+8*(8-first);ap.gr_offs=-(int32_t)(8*(8-first));
        if(uc_mem_write(uc,storage,&ap,sizeof ap)||uc_mem_write(uc,storage+64,registers,8*(8-first))){e->stop=1;uc_emu_stop(uc);return;}
        int length=guest_vsnprintf(e,a0,a1,checked?rdreg(uc,UC_ARM64_REG_X4):a2,storage);
        if(length<0){e->stop=1;uc_emu_stop(uc);return;}
        RET((uint64_t)length);
    }
    if(!strcmp(name,"asprintf") || !strcmp(name,"vasprintf")){
        uint64_t va=a2,storage=MISC_BASE+0x805000;
        if(!strcmp(name,"asprintf")){
            uint64_t registers[6];
            for(unsigned i=0;i<6;i++)registers[i]=rdreg(uc,UC_ARM64_REG_X0+2+i);
            guest_va_t ap={0};ap.stack=rdreg(uc,R_SP);ap.gr_top=storage+64+sizeof registers;ap.gr_offs=-(int32_t)sizeof registers;
            if(uc_mem_write(uc,storage,&ap,sizeof ap)||uc_mem_write(uc,storage+64,registers,sizeof registers)){e->stop=1;uc_emu_stop(uc);return;}
            va=storage;
        }
        uint64_t result=heap_alloc(e,16384,0);
        int length=guest_vsnprintf(e,result,16384,a1,va);
        if(length<0||uc_mem_write(uc,a0,&result,8)){e->stop=1;uc_emu_stop(uc);return;}
        RET((uint64_t)length);
    }
    if(!strcmp(name, "sscanf"))                    RET((uint64_t)emu_sscanf(e, a0, a1));
    if(!strcmp(name, "vsscanf"))                   RET0();
    if(!strcmp(name, "strerror") || !strcmp(name, "strerror_r")) RET0();
    if(!strcmp(name, "qsort"))                     RET0();
    if(!strcmp(name, "fopen")){
        static char fpath[512], fmode[64];
        read_cstr(e, a0, fpath, sizeof fpath);
        read_cstr(e, a1, fmode, sizeof fmode);
        size_t clen = 0;
        const char *content = path_content(e, fpath, &clen);
        if(!content && fmode[0]!='w' && fmode[0]!='a'){
            uint32_t error=2;uc_mem_write(uc,e->errno_addr,&error,4);RET0();
        }
        if(e->nfiles < MAX_FILES){
            fakefile_t *ff = &e->files[e->nfiles++];
            ff->kind = 1; ff->fd = 0; ff->rnd = is_rnd_path(fpath);
            snprintf(ff->path, sizeof ff->path, "%s", fpath);
            ff->content = (char *)malloc(clen + 1);
            if(content) memcpy(ff->content, content, clen);
            ff->len = clen; ff->pos = 0;
            VLOG("    [fopen] '%s' mode='%s' (%zu bytes)\n", fpath, fmode, clen);
            RET(MISC_BASE + 0x4000 + (uint64_t)(e->nfiles - 1) * 0x100);
        }
        RET0();
    }
    if(!strcmp(name, "fclose")){
        fakefile_t *ff = file_by_fp(e, a0);
        if(ff){ free(ff->content); ff->content = NULL; ff->kind = 0; }
        RET0();
    }
    if(!strcmp(name, "fgets")){
        fakefile_t *ff = file_by_fp(e, a2);
        if(!ff || !ff->content || ff->pos >= ff->len) RET0();
        char *nl = memchr(ff->content + ff->pos, '\n', ff->len - ff->pos);
        size_t end = nl ? (size_t)(nl - ff->content) : ff->len;
        size_t l = end - ff->pos + (nl ? 1 : 0);
        if(l > a1 - 1) l = a1 - 1;
        uc_mem_write(uc, a0, ff->content + ff->pos, l);
        uint8_t z = 0; uc_mem_write(uc, a0 + l, &z, 1);
        ff->pos = end + (nl ? 1 : 0);
        RET(a0);
    }
    if(!strcmp(name, "fread")){
        fakefile_t *ff = file_by_fp(e, a3);
        if(!ff || !ff->content) RET0();
        uint64_t want = a1 * a2;
        size_t avail = ff->len > ff->pos ? ff->len - ff->pos : 0;
        size_t got = want < avail ? (size_t)want : avail;
        uc_mem_write(uc, a0, ff->content + ff->pos, got);
        ff->pos += got;
        VLOG("    [fread] '%s' sz=%llu got=%zu\n", ff->path, (unsigned long long)a1, got);
        RET(a1 ? (uint64_t)(got / a1) : 0);
    }
    if(!strcmp(name, "fwrite"))                    RET(a2);
    if(!strcmp(name, "fseek")){
        fakefile_t *ff = file_by_fp(e, a0);
        if(ff){
            if(a2 == 0) ff->pos = a1;
            else if(a2 == 1) ff->pos += a1;
            else ff->pos = ff->len + a1;
        }
        RET0();
    }
    if(!strcmp(name, "ftell")){
        fakefile_t *ff = file_by_fp(e, a0);
        RET(ff ? ff->pos : 0);
    }
    if(!strcmp(name, "feof")){
        fakefile_t *ff = file_by_fp(e, a0);
        RET(ff && ff->pos >= ff->len ? 1 : 0);
    }
    if(!strcmp(name, "ferror"))                    RET0();
    if(!strcmp(name, "fstat")){
        RET(guest_fstat(e,a0,a1));
    }
    if(!strcmp(name,"stat") || !strcmp(name,"stat64")) RET(guest_stat_path(e,a0,a1));
    if(!strcmp(name,"access") || !strcmp(name,"faccessat")){
        uint64_t path_addr=!strcmp(name,"access")?a0:a1;
        int rc=guest_stat_path(e,path_addr,MISC_BASE+0x804000);
        char path[512]="";read_cstr(e,path_addr,path,sizeof path);
        VLOG("    [access] %s -> %d\n",path,rc? -1:0);
        RET(rc?-1:0);
    }
    if(!strcmp(name, "fputs") || !strcmp(name, "fputc") || !strcmp(name, "fflush") ||
       !strcmp(name, "getc") || !strcmp(name, "getwc") || !strcmp(name, "__fgets_chk") ||
       !strcmp(name, "fputwc"))                    RET0();
    if(!strcmp(name, "uname")){
        if(a0){
            uint8_t buf[390]; memset(buf, 0, sizeof buf);
            memcpy(buf, "Linux", 5);
            memcpy(buf + 65, "4.9.0", 5);
            memcpy(buf + 130, "#1 SMP", 6);
            uc_mem_write(uc, a0, buf, sizeof buf);
        }
        RET0();
    }
    if(!strcmp(name, "__android_log_write"))       RET0();
    if(!strcmp(name, "sigaction") || !strcmp(name, "signal")) RET0();
    if(!strcmp(name, "openlog") || !strcmp(name, "closelog") ||
       !strcmp(name, "syslog") || !strcmp(name, "vsyslog")) RET0();
    if(!strcmp(name, "fork") || !strcmp(name, "vfork")){
        /* fork(): the child continues at the return address with x0==0 and
         * inherits memory + fds.  We model it as a cooperatively scheduled
         * context so the parent can keep running its own thread. */
        if(e->nth < MAX_THREADS){
            int ci = e->nth++;
            thread_t *t = &e->th[ci];
            ctx_save_regs(e, t->regs, &t->sp, &t->pc);
            t->regs[0] = 0;                        /* fork() == 0 in the child */
            t->pc = lr;
            t->state = 1;
            t->pid = 0x1000;
            t->ppid = guest_pid(e);
            t->bfd = t->bbuf = t->blen = 0;
            uc_reg_read(e->uc, UC_ARM64_REG_TPIDR_EL0, &t->tls);
            t->fork_heap_next = e->heap_next;
            t->fork_mem = fork_mem_save(e, &t->nfork_mem);
            if(!t->fork_mem || uc_context_alloc(e->uc, &t->cpu) ||
               uc_context_save(e->uc, t->cpu)){
                t->state = 3;
                RET((uint64_t)-1);
            }
            uc_context_reg_write(t->cpu, R_X0, &t->regs[0]);
            uc_context_reg_write(t->cpu, R_PC, &t->pc);
        }
        VLOG("    [stub] %s -> 4096 (parent) + child context\n", name);
        RET(0x1000);
    }
    if(!strcmp(name, "killpg") || !strcmp(name, "prctl")) RET0();
    if(!strcmp(name, "__system_property_get")){
        char pn[256] = "";
        read_cstr(e, a0, pn, sizeof pn);
        const char *val = "";
        if(!strcmp(pn, "ro.build.version.sdk"))        val = "30";
        else if(!strcmp(pn, "ro.kernel.version"))      val = "4.14.190";
        else if(!strcmp(pn, "ro.product.manufacturer"))val = "Google";
        else if(!strcmp(pn, "ro.product.model"))       val = "Pixel 5";
        else if(!strcmp(pn, "ro.product.device"))      val = "redfin";
        else if(!strcmp(pn, "ro.build.fingerprint"))
            val = "google/redfin/redfin:11/RQ3A.211001.001/7641976:user/release-keys";
        else if(!strcmp(pn, "ro.build.tags"))          val = "release-keys";
        else if(!strcmp(pn, "ro.build.type"))          val = "user";
        else if(!strcmp(pn, "ro.debuggable"))          val = "0";
        else if(!strcmp(pn, "ro.secure"))              val = "1";
        VLOG("    [prop] '%s' -> '%s'\n", pn, val);
        if(a1) uc_mem_write(uc, a1, val, strlen(val) + 1);
        RET(strlen(val));
    }
    if(!strcmp(name,"dladdr")){
        for(const emu_t *image=e;image;image=image==e?e->peer:NULL){
            for(int i=0;i<image->nsegs;i++){
                uint64_t start=image->load_bias+image->segs[i].va;
                if(a0<start || a0-start>=image->segs[i].memsz)continue;
                const char *name=image->image_name?image->image_name:"libsupercell_brawlstars.so";
                char full[512];snprintf(full,sizeof full,"%s/%s",guest_game(e)->native,name);
                uint64_t path=heap_alloc(e,strlen(full)+1,0);write_cstr(e,path,full);
                uint64_t info[4]={path,image->load_bias,0,0};
                if(uc_mem_write(uc,a1,info,sizeof info)) RET0();
                RET(1);
            }
        }
        RET0();
    }
    if(!strcmp(name, "execl"))                     RET((uint64_t)-1);
    if(!strcmp(name, "eventfd"))                   RET(0x55);
    if(!strcmp(name, "inotify_init") || !strcmp(name, "inotify_init1")) RET(0x66);
    if(!strcmp(name, "inotify_add_watch"))         RET0();
    if(!strcmp(name, "open") || !strcmp(name, "openat")){
        static char opath[512];
        uint64_t paddr = (!strcmp(name, "openat")) ? a1 : a0;
        read_cstr(e, paddr, opath, sizeof opath);
        size_t clen = 0;
        const char *content = path_content(e, opath, &clen);
        uint64_t flags=!strcmp(name,"openat")?a2:a1;
        if(!content && !(flags&0x40)){
            uint32_t error=2;uc_mem_write(uc,e->errno_addr,&error,4);
            VLOG("    [open missing] %s\n",opath);RET(-1);
        }
        if(e->nfiles < MAX_FILES){
            fakefile_t *ff = &e->files[e->nfiles++];
            ff->kind = 2; ff->fd = 0x77 + (int)(e->nfiles - 1);
            ff->rnd = is_rnd_path(opath);
            snprintf(ff->path, sizeof ff->path, "%s", opath);
            ff->content = (char *)malloc(clen + 1);
            if(content) memcpy(ff->content, content, clen);
            ff->len = clen; ff->pos = 0;
            VLOG("    [open] '%s' flags=0x%llx fd=%d\n", opath, (unsigned long long)a1, ff->fd);
            RET((uint64_t)ff->fd);
        }
        RET0();
    }
    if(!strcmp(name, "read")){
        fakefile_t *ff = file_by_fd(e, a0);
        if(!ff) RET0();
        if(ff->rnd){
            if(a1 && a2){
                uint8_t *tmp = (uint8_t *)malloc(a2);
                fill_rnd(tmp, a2);
                uc_mem_write(uc, a1, tmp, a2);
                free(tmp);
            }
            VLOG("    [read] fd=%llu '%s' got=%llu (random)\n",
                 (unsigned long long)a0, ff->path, (unsigned long long)a2);
            RET(a2);
        }
        if(!ff->content) RET0();
        size_t avail = ff->len > ff->pos ? ff->len - ff->pos : 0;
        size_t got = a2 < avail ? (size_t)a2 : avail;
        if(a1 && got) uc_mem_write(uc, a1, ff->content + ff->pos, got);
        ff->pos += got;
        VLOG("    [read] fd=%llu '%s' got=%zu\n",
             (unsigned long long)a0, ff->path, got);
        RET(got);
    }
    if(!strcmp(name, "close")){
        fakefile_t *ff = file_by_fd(e, a0);
        if(ff){ free(ff->content); ff->content = NULL; ff->kind = 0; }
        RET0();
    }
    if(!strcmp(name, "lseek")){
        fakefile_t *ff = file_by_fd(e, a0);
        RET(file_seek(ff,(int64_t)a1,a2));
    }
    if(!strcmp(name, "cacheflush")) RET0();
    if(!strcmp(name, "tgkill"))                    RET0();
    if(!strcmp(name, "waitpid") || !strcmp(name, "wait4")){
        if(e->trace_pid && ((int32_t)a0 == -1 || a0 == e->trace_pid)){
            if(e->trace_pending){
                if(a1) uc_mem_write(e->uc, a1, &e->trace_status, 4);
                e->trace_pending = 0;
                RET(e->trace_pid);
            }
            if(a2 & 1) RET0();                   /* WNOHANG */
            if(e->cur_ctx){
                thread_t *t = &e->th[e->cur_ctx - 1];
                t->wait_pid = 1;
                t->wait_status = a1;
                t->state = 2;
                wrreg(uc, R_PC, lr);
                uc_emu_stop(uc);
                return;
            }
        }
        VLOG("    [stub] %s(pid=%lld, status=0x%llx) -> -1 (ctx %d)\n", name,
             (long long)a0, (unsigned long long)a1, e->cur_ctx);
        RET((uint64_t)-1);
    }
    if(!strcmp(name, "sigemptyset") || !strcmp(name, "sigfillset") ||
       !strcmp(name, "sigprocmask"))               RET0();
    /* catch-all */
    VLOG("    [stub] %s -> 0 (ctx %d lr=0x%llx)\n", name, e->cur_ctx, (unsigned long long)lr);
    RET0();
    #undef RET
    #undef RET0
}

/* ------------------------------------------------------------------ */
/* hooks                                                               */

static void dispatch_stub_at(emu_t *e, uint64_t addr){
    for(int i = 0; i < e->nstubs; i++)
        if(e->stubs[i].addr == addr){ dispatch_import(e, e->stubs[i].name); return; }
    VLOG("[!] no stub registered at 0x%llx (nstubs=%d)\n",
         (unsigned long long)addr, e->nstubs);
}

static void hook_code_stubs(uc_engine *uc, uint64_t addr, uint32_t size, void *ud){
    (void)size; (void)uc;
    emu_t *e = (emu_t *)ud;
    if(addr < STUB_BASE || addr >= STUB_BASE + STUB_SIZE) return;
    dispatch_stub_at(e, addr);
}

static int ctx_plausible(const uint8_t *b, int size);

/* Capture a context-shaped native copy. Sizes come from its actual arguments;
 * the 0x170-byte header / uint32 table geometry belongs to the WB format. */
static void hook_code_gen(uc_engine *uc, uint64_t addr, uint32_t size, void *ud){
    (void)size;
    emu_t *e = (emu_t *)ud;
    if(addr >= STUB_BASE && addr < STUB_BASE + STUB_SIZE){
        dispatch_stub_at(e, addr);
        return;
    }
    uint64_t x2 = rdreg(uc, R_X2);
    uint32_t insn = 0;
    uc_mem_read(uc, addr, &insn, sizeof insn);
    int call = (insn & 0xfc000000u) == 0x94000000u ||
               (insn & 0xfffffc1fu) == 0xd63f0000u;
    if(call && x2 >= 0x170 + 0x400 + 4 && x2 <= 1048576 &&
       (x2 - 4 - 0x170) % 0x400 == 0 && e->ncaptures < 16){
        uint64_t x1 = rdreg(uc, R_X1);
        size_t ctx_size = (size_t)x2 - 4;
        uint8_t *buf = (uint8_t *)malloc(ctx_size);
        if(buf && !uc_mem_read(uc, x1, buf, ctx_size) && ctx_plausible(buf,(int)ctx_size)){
            e->captures[e->ncaptures] = buf;
            e->capture_size[e->ncaptures] = ctx_size;
            e->capture_site[e->ncaptures] = addr;
            e->ncaptures++;
            fprintf(stderr, "[*] generator capture at call 0x%llx (%zu bytes)\n",
                    (unsigned long long)addr, ctx_size);
            uc_emu_stop(uc);
        } else free(buf);
    }
}

/* ------------------------------------------------------------------ */
/* raw syscalls (svc #0): the protector's later stages bypass libc     */

static void hook_intr(uc_engine *uc, uint32_t intno, void *ud){
    emu_t *e = (emu_t *)ud;
    if(intno != 2){                              /* ARM_EXCP_SWI (svc) */
        if(e->cur_ctx == 0 && e->trace_pid && (intno == 1 || intno == 7)){
            e->trace_status = ((intno == 1 ? 4u : 5u) << 8) | 0x7f;
            e->trace_pending = e->trace_stopped = 1;
            VLOG("    [trace stop] exception=%u pc=0x%llx\n", intno,
                 (unsigned long long)rdreg(uc, R_PC));
            uc_emu_stop(uc);
            return;
        }
        fprintf(stderr, "error: unhandled guest exception %u at pc=0x%llx lr=0x%llx (ctx %d)\n",
                intno, (unsigned long long)rdreg(uc, R_PC),
                (unsigned long long)rdreg(uc, R_X30), e->cur_ctx);
        e->stop = 1;
        uc_emu_stop(uc);
        return;
    }
    uint64_t nr = rdreg(uc, UC_ARM64_REG_X8);
    uint64_t a0 = rdreg(uc, R_X0), a1 = rdreg(uc, R_X1), a2 = rdreg(uc, R_X2),
             a3 = rdreg(uc, UC_ARM64_REG_X3);
    (void)a3;
    int64_t ret = -38;                           /* -ENOSYS */
    switch(nr){
    case 56: {                                   /* openat(dirfd,path,flags,mode) */
        char path[512] = "";
        read_cstr(e, a1, path, sizeof path);
        size_t clen = 0;
        const char *content = path_content(e, path, &clen);
        if(!content && !(a2&0x40)){VLOG("    [sys openat missing] %s\n",path);ret=-2;break;}
        if(e->nfiles < MAX_FILES){
            fakefile_t *ff = &e->files[e->nfiles++];
            ff->kind = 2; ff->fd = 0x77 + (int)(e->nfiles - 1);
            ff->rnd = is_rnd_path(path);
            snprintf(ff->path, sizeof ff->path, "%s", path);
            ff->content = (char *)malloc(clen + 1);
            if(content) memcpy(ff->content, content, clen);
            ff->len = clen; ff->pos = 0;
            VLOG("    [sys openat] '%s' flags=0x%llx fd=%d lr=0x%llx\n", path,
                 (unsigned long long)a2, ff->fd,
                 (unsigned long long)rdreg(uc, R_X30));
            ret = ff->fd;
        } else ret = -24;                        /* -EMFILE */
        break;
    }
    case 57: {                                   /* close */
        fakefile_t *ff = file_by_fd(e, a0);
        if(ff){ free(ff->content); ff->content = NULL; ff->kind = 0; }
        ret = 0;
        break;
    }
    case 61: {                                   /* getdents64 */
        fakefile_t *ff=file_by_fd(e,a0);
        if(!ff){ret=-9;break;}
        if(strcmp(ff->path,"/proc/self/task")&&strcmp(ff->path,"/proc/1234/task")){ret=-20;break;}
        const char *names[]={".","..","1234"};size_t used=0;
        while(ff->pos<3){
            const char *name=names[ff->pos];
            uint16_t length=(uint16_t)((19+strlen(name)+1+7)&~7u);
            if(length>a2-used)break;
            uint8_t entry[32]={0};uint64_t ino=ff->pos+1,next=ff->pos+1;
            memcpy(entry,&ino,8);memcpy(entry+8,&next,8);memcpy(entry+16,&length,2);
            entry[18]=4;memcpy(entry+19,name,strlen(name)+1);
            if(uc_mem_write(uc,a1+used,entry,length)){ret=-14;break;}
            used+=length;ff->pos++;
        }
        ret=used? (int64_t)used:ff->pos<3?-22:0;
        break;
    }
    case 63: {                                   /* read */
        chan_t *ch = chan_by_rfd(e, a0);
        if(ch){
            if(ch->len == 0){
                /* no data yet: park this context until a thread writes */
                if(e->cur_ctx == 0){
                    e->blk.active = 1; e->blk.fd = a0; e->blk.buf = a1; e->blk.len = a2;
                } else {
                    thread_t *t = &e->th[e->cur_ctx - 1];
                    t->state = 2; t->bfd = a0; t->bbuf = a1; t->blen = a2;
                }
                VLOG("    [sys read] fd=%llu len=%llu would block (ctx %d)\n",
                     (unsigned long long)a0, (unsigned long long)a2, e->cur_ctx);
                uc_emu_stop(uc);
                return;
            }
            ret = (int64_t)chan_read_guest(e, ch, a1, (size_t)a2);
            VLOG("    [sys read] fd=%llu (pipe) got=%lld lr=0x%llx ctx=%d\n",
                 (unsigned long long)a0, (long long)ret,
                 (unsigned long long)rdreg(uc, R_X30), e->cur_ctx);
            break;
        }
        fakefile_t *ff = file_by_fd(e, a0);
        if(ff && ff->rnd){
            if(a1 && a2){
                uint8_t *tmp = (uint8_t *)malloc(a2);
                fill_rnd(tmp, a2);
                uc_mem_write(uc, a1, tmp, a2);
                free(tmp);
            }
            ret = (int64_t)a2;
            break;
        }
        if(!ff || !ff->content){
            VLOG("    [sys read] fd=%llu -> 0 (unknown fd)\n", (unsigned long long)a0);
            ret = 0; break;
        }
        size_t avail = ff->len > ff->pos ? ff->len - ff->pos : 0;
        size_t got = a2 < avail ? (size_t)a2 : avail;
        if(a1 && got) uc_mem_write(uc, a1, ff->content + ff->pos, got);
        ff->pos += got;
        VLOG("    [sys read] fd=%llu got=%zu lr=0x%llx\n",
             (unsigned long long)a0, got, (unsigned long long)rdreg(uc, R_X30));
        ret = (int64_t)got;
        break;
    }
    case 64: {                                   /* write */
        if(g_verbose && a2){
            uint8_t tmp[16]; size_t k = a2 < sizeof tmp ? (size_t)a2 : sizeof tmp;
            uc_mem_read(uc, a1, tmp, k);
            fprintf(stderr, "    [sys write raw] fd=%llu buf=0x%llx len=%llu:",
                    (unsigned long long)a0, (unsigned long long)a1,
                    (unsigned long long)a2);
            for(size_t i = 0; i < k; i++) fprintf(stderr, " %02x", tmp[i]);
            fprintf(stderr, "\n");
        }
        chan_t *ch = chan_by_wfd(e, a0);
        if(ch){
            size_t got = chan_write_guest(e, ch, a1, (size_t)a2);
            VLOG("    [sys write] fd=%llu (pipe) %zu bytes lr=0x%llx ctx=%d\n",
                 (unsigned long long)a0, got,
                 (unsigned long long)rdreg(uc, R_X30), e->cur_ctx);
            ret = (int64_t)got;
            break;
        }
        ret = (int64_t)a2;
        break;
    }
    case 62: {                                   /* lseek */
        fakefile_t *ff = file_by_fd(e, a0);
        ret=file_seek(ff,(int64_t)a1,a2);
        break;
    }
    case 80:                                     /* fstat(fd, statbuf) */
        ret=guest_fstat(e,a0,a1);break;
    case 79:                                     /* newfstatat(dirfd,path,buf,flags) */
        ret=guest_stat_path(e,a1,a2);break;
    case 222: {                                  /* mmap */
        ret=guest_mmap(e,a1,a3,rdreg(uc,UC_ARM64_REG_X4),rdreg(uc,UC_ARM64_REG_X5));
        break;
    }
    case 22: case 59: {                          /* pipe / pipe2 */
        chan_t *c = chan_new(e);
        if(!c){ ret = -24; break; }
        uint32_t fds[2] = { (uint32_t)c->rfd, (uint32_t)c->wfd };
        if(a0) uc_mem_write(uc, a0, fds, 8);
        VLOG("    [sys pipe2] fds=%u,%u\n", fds[0], fds[1]);
        ret = 0; break;
    }
    case 220:
        VLOG("    [sys clone] flags=0x%llx -> parent path\n", (unsigned long long)a0);
        ret = 0x1000; break;                     /* clone/fork: parent path */
    case 199: {                                  /* socketpair (bidirectional) */
        chan_t *ab = chan_new(e), *ba = chan_new(e);
        if(!ab || !ba){ ret = -24; break; }
        int x = ab->rfd, y = ba->rfd;
        ab->rfd = x; ab->wfd = y;               /* write y -> read x */
        ba->rfd = y; ba->wfd = x;               /* write x -> read y */
        uint32_t fds[2] = { (uint32_t)x, (uint32_t)y };
        if(a3) uc_mem_write(uc, a3, fds, 8);
        VLOG("    [sys socketpair] -> %d,%d\n", x, y);
        ret = 0; break;
    }
    case 19: ret = 0x9b; break;                  /* eventfd2 */
    case 20: ret = 0x9c; break;                  /* epoll_create1 */
    case 23: ret = 0x9d; break;                  /* dup */
    case 25: ret = 0; break;                     /* fcntl */
    case 198: ret = 0x9e; break;                 /* socket */
    case 134: ret = 0; break;                    /* rt_sigaction */
    case 135: ret = 0; break;                    /* rt_sigprocmask */
    case 132: ret = 0; break;                    /* rt_sigpending */
    case 133: ret = -4; break;                   /* rt_sigsuspend -> -EINTR */
    case 130: ret = 0; break;                    /* tkill */
    case 226: ret = 0; break;                    /* mprotect */
    case 215: ret = 0; break;                    /* munmap */
    case 117:
        VLOG("    [sys ptrace] request=0x%llx pid=%lld addr=0x%llx data=0x%llx ctx=%d\n",
             (unsigned long long)a0, (long long)(int32_t)a1,
             (unsigned long long)a2, (unsigned long long)a3, e->cur_ctx);
        /* Attaching a nonpositive PID fails with ESRCH, not EPERM. */
        ret = trace_ptrace(e, a0, a1, a2, a3);
        break;
    case 173: ret = guest_ppid(e); break;         /* getppid */
    case 178: ret = 1234; break;                 /* gettid */
    case 172: ret = guest_pid(e); break;          /* getpid */
    case 167: ret = 0; break;                    /* prctl */
    case 174: case 175: case 176: case 177:       /* ordinary Android app UID/GID */
        ret=10123;break;
    case 131: ret = 0; break;                    /* tgkill */
    case 129: ret = 0; break;                    /* kill */
    case 48:                                    /* faccessat */
        ret=guest_stat_path(e,a1,MISC_BASE+0x804000);break;
    case 78:  ret = -2; break;                   /* readlinkat -> -ENOENT */
    case 113:                                    /* clock_gettime */
        ret=guest_clock(e,a1,a0==0,0);break;
    case 169:                                    /* gettimeofday */
        ret=a0?guest_clock(e,a0,1,1):0;break;
    case 160:                                    /* uname */
        if(a0){
            uint8_t buf[390]; memset(buf, 0, sizeof buf);
            memcpy(buf, "Linux", 5); memcpy(buf + 65, "4.9.0", 5);
            memcpy(buf + 130, "#1 SMP", 6);
            uc_mem_write(uc, a0, buf, sizeof buf);
        }
        ret = 0; break;
    case 93: case 94:                            /* exit / exit_group */
        VLOG("    [sys exit] code=%llu (ctx %d lr=0x%llx)\n",
             (unsigned long long)a0, e->cur_ctx,
             (unsigned long long)rdreg(uc, R_X30));
        if(e->cur_ctx == 0) e->stop = 1;
        else e->th[e->cur_ctx - 1].state = 3;
        uc_emu_stop(uc);
        ret = 0; break;
    default:
        VLOG("    [sys %llu] a0=0x%llx a1=0x%llx a2=0x%llx lr=0x%llx -> -ENOSYS\n",
             (unsigned long long)nr, (unsigned long long)a0,
             (unsigned long long)a1, (unsigned long long)a2,
             (unsigned long long)rdreg(uc, R_X30));
        break;
    }
    if(e->stop) return;
    wrreg(uc, R_X0, (uint64_t)ret);
}

/* ------------------------------------------------------------------ */
/* startup phases: ctor + JNI_OnLoad                                   */

static void setup_regs(uc_engine *uc, uint64_t entry, uint64_t lr, uint64_t x0,
                       uint64_t sp, uint64_t x8){
    for(int i=0;i<29;i++) wrreg(uc, UC_ARM64_REG_X0+i, 0);
    wrreg(uc, R_SP, sp);
    wrreg(uc, R_X29, sp);
    wrreg(uc, R_X30, lr);
    wrreg(uc, R_X0, x0);
    wrreg(uc, R_X1, 0);
    if(x8) wrreg(uc, UC_ARM64_REG_X8, x8);
    wrreg(uc, R_PC, entry);
}

static int run_unpack(emu_t *e){
    uint64_t table=JVM_TABLE;uc_mem_write(e->uc,JNI_VM,&table,8);
    table=JNI_TABLE;uc_mem_write(e->uc,JNI_ENV,&table,8);
    for(int i=4;i<234;i++){
        char name[24];snprintf(name,sizeof name,"jni_%d",i);
        uint64_t fn=stub_for(e,name);uc_mem_write(e->uc,JNI_TABLE+(uint64_t)i*8,&fn,8);
    }
    uint64_t getenv_fn=stub_for(e,"jvm_GetEnv");
    uc_mem_write(e->uc,JVM_TABLE+6*8,&getenv_fn,8);
    uint64_t attach_fn=stub_for(e,"jvm_AttachCurrentThread"),detach_fn=stub_for(e,"jvm_DetachCurrentThread");
    uc_mem_write(e->uc,JVM_TABLE+4*8,&attach_fn,8);
    uc_mem_write(e->uc,JVM_TABLE+5*8,&detach_fn,8);
    uc_mem_write(e->uc,JVM_TABLE+7*8,&attach_fn,8);
    uint64_t tags[64]; memset(tags, 0, sizeof tags);
    if(dyn_tags(e, tags) < 0){
        fprintf(stderr, "error: no PT_DYNAMIC\n");
        return -1;
    }
    uint64_t init_va = tags[25], init_sz = tags[27];
    if(!init_va || !init_sz){
        fprintf(stderr, "error: no DT_INIT_ARRAY\n");
        return -1;
    }
    uint64_t entry = 0;
    uc_mem_read(e->uc, init_va, &entry, 8);       /* post-relocation slot */
    if(!entry){
        fprintf(stderr, "error: DT_INIT_ARRAY slot is 0\n");
        return -1;
    }
    VLOG("[*] constructor at 0x%llx\n", (unsigned long long)entry);

    uc_hook hstub, hintr;
    uc_err hrc = uc_hook_add(e->uc, &hstub, UC_HOOK_CODE, hook_code_stubs, e,
                             STUB_BASE, STUB_BASE + STUB_SIZE);
    if(hrc) fprintf(stderr, "error: stub hook registration failed (%s)\n", uc_strerror(hrc));
    uc_hook_add(e->uc, &hintr, UC_HOOK_INTR, hook_intr, e, 1, 0);

    uint64_t jni = 0;
    for(int i = 0; i < e->nsyms; i++)
        if(e->symnames && e->symnames[i] && !strcmp(e->symnames[i], "JNI_OnLoad")){
            long sf = va2file(e, e->symtab);
            if(sf >= 0) jni = rd64(e->raw, (size_t)sf + (size_t)i*24 + 8);
            break;
        }

    const uint64_t chunk = 2000000ULL;
    int phase = 1;
    uint64_t phase2_start = 0;
    const uint64_t total_budget=e->startup_budget?e->startup_budget+600000000ULL:600000000ULL;
    time_t t0 = time(NULL);
    setup_regs(e->uc, entry, SENT_CTOR, 0, STACK_TOP - 0x1000, 0);
    while(!e->stop && phase <= 2 && e->insn_count < total_budget && time(NULL) - t0 < 900){
        uc_err rc = uc_emu_start(e->uc, entry, 0, 0, chunk);
        e->insn_count += chunk;
        uint64_t pc = rdreg(e->uc, R_PC);
        VLOG("[.] phase %d insns=%llu pc=0x%llx\n", phase,
             (unsigned long long)e->insn_count, (unsigned long long)pc);
        if((rc == UC_ERR_FETCH_UNMAPPED || rc == UC_ERR_OK) &&
           (pc == SENT_CTOR || pc == SENT_JNI)){
            if(pc == SENT_CTOR && phase == 1){
                if(jni){
                    VLOG("[*] ctor returned (%llu insns); JNI_OnLoad at 0x%llx\n",
                         (unsigned long long)e->insn_count, (unsigned long long)jni);
                    setup_regs(e->uc, jni, SENT_JNI, JNI_VM,
                               STACK_TOP - 0x2000, 0);
                    entry = jni; phase = 2; phase2_start = e->insn_count;
                    continue;
                }
                VLOG("[*] ctor returned; no exported JNI_OnLoad\n");
                break;
            }
            VLOG("[*] JNI_OnLoad returned 0x%llx (%llu insns)\n",(unsigned long long)rdreg(e->uc,R_X0),
                 (unsigned long long)e->insn_count);
            break;
        }
        if(rc && rc != UC_ERR_OK && rc != UC_ERR_FETCH_UNMAPPED){
            if(phase == 2){
                fprintf(stderr, "[!] JNI_OnLoad phase stopped early (pc=0x%llx %s); "
                        "keeping constructor results\n",
                        (unsigned long long)pc, uc_strerror(rc));
                break;
            }
            fprintf(stderr, "error: emulation stopped (pc=0x%llx %s)\n",
                    (unsigned long long)pc, uc_strerror(rc));
            return -1;
        }
        if(rc == UC_ERR_FETCH_UNMAPPED && pc != SENT_CTOR && pc != SENT_JNI){
            if(phase == 2){
                fprintf(stderr, "[!] JNI_OnLoad jumped to unmapped 0x%llx; "
                        "keeping constructor results\n", (unsigned long long)pc);
                break;
            }
            fprintf(stderr, "error: jumped to unmapped memory (pc=0x%llx)\n",
                    (unsigned long long)pc);
            return -1;
        }
        if(phase == 2 && e->insn_count - phase2_start > (e->startup_budget?e->startup_budget:240000000ULL)){
            fprintf(stderr, "[!] JNI_OnLoad reached the instruction budget; keeping "
                    "constructor results\n");
            break;
        }
        if(pc == SENT_CTOR || pc == SENT_JNI) break;

        if(e->trace_stopped && !e->blk.active){
            for(int round = 0; round < 32 && e->trace_stopped && !e->stop; round++){
                if(!run_threads_once(e)) break;
            }
            if(e->trace_stopped){
                fprintf(stderr, "error: tracer did not resume stopped guest\n");
                break;
            }
            entry = rdreg(e->uc, R_PC);
            continue;
        }

        /* the main thread parked on an empty pipe: run the worker threads
         * until somebody feeds it, then complete the pending read */
        if(e->blk.active){
            for(int round = 0; round < 32 && e->blk.active; round++){
                if(!run_threads_once(e)) break;
                chan_t *ch = chan_by_rfd(e, e->blk.fd);
                if(ch && ch->len){
                    size_t got = chan_read_guest(e, ch, e->blk.buf, (size_t)e->blk.len);
                    wrreg(e->uc, R_X0, got);
                    VLOG("[*] main unblocked: %zu byte(s) from a worker\n", got);
                    e->blk.active = 0;
                }
            }
            if(e->blk.active){
                fprintf(stderr, "[!] deadlock: no thread feeds fd %llu; "
                        "stopping startup phase\n", (unsigned long long)e->blk.fd);
                e->blk.active = 0;
                e->stop = 0;
                break;
            }
            uint64_t npc = rdreg(e->uc, R_PC);
            entry = npc;
            continue;
        }

        if(e->yield_workers){
            e->yield_workers=0;
            run_threads_once(e);
        }
        entry = pc;                                /* continue from current pc */
    }
    if(e->stop){
        if(phase == 1) return -1;
        VLOG("[!] process exited during JNI_OnLoad; keeping what it produced\n");
        e->stop = 0;
    }
    if(e->insn_count >= total_budget || time(NULL) - t0 >= 900){
        fprintf(stderr, "error: startup emulation exceeded budget\n");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* relocations                                                         */

static uint64_t relocated_symbol(emu_t *e,uint32_t index){
    long sf=va2file(e,e->symtab);
    if(sf>=0 && index<(uint32_t)e->nsyms){
        size_t p=(size_t)sf+(size_t)index*24;
        uint16_t section=0;
        if(p+24>e->raw_len)return 0;
        memcpy(&section,e->raw+p+6,2);
        if(section) return rd64(e->raw,p+8)+e->load_bias;
    }
    const char *name=symname(e,(int)index);
    return *name ? stub_for(e,name) : 0;
}

static int apply_relocations(emu_t *e){
    uint64_t tags[64]; memset(tags, 0, sizeof tags);
    if(dyn_tags(e, tags) < 0) return -1;
    uint64_t rela_va = tags[7], relasz = tags[8], jmp_va = tags[23], jmp_sz = tags[2];
    long rf = va2file(e, rela_va), jf = va2file(e, jmp_va);
    VLOG("[*] reloc: RELA va=0x%llx sz=%llu file=%ld | JMPREL va=0x%llx sz=%llu file=%ld | syms=%d\n",
         (unsigned long long)rela_va,(unsigned long long)relasz,rf,
         (unsigned long long)jmp_va,(unsigned long long)jmp_sz,jf,e->nsyms);
    if(rela_va && rf < 0) return -1;
    if(jmp_va && jf < 0) return -1;

    if(rela_va){
        for(size_t k = 0; k < relasz/24; k++){
            size_t o = (size_t)rf + k*24;
            uint64_t r_offset = rd64(e->raw, o);
            uint64_t r_info   = rd64(e->raw, o+8);
            int64_t  r_addend; memcpy(&r_addend, e->raw + o + 16, 8);
            uint32_t type = (uint32_t)(r_info & 0xffffffff);
            uint32_t sidx = (uint32_t)(r_info >> 32);
            uint64_t val = 0;
            if(type == 1025) VLOG("    GLOB_DAT off=0x%llx sym=%u name='%s'\n",
                (unsigned long long)r_offset, sidx, symname(e,(int)sidx));
            if(type == 1027) val = (uint64_t)r_addend+e->load_bias; /* RELATIVE */
            else if(type == 1025){                            /* GLOB_DAT */
                val = relocated_symbol(e,sidx)+(uint64_t)r_addend;
            } else continue;
            uc_mem_write(e->uc, r_offset+e->load_bias, &val, 8);
        }
    }
    if(jmp_va){
        for(size_t k = 0; k < jmp_sz/24; k++){
            size_t o = (size_t)jf + k*24;
            uint64_t r_offset = rd64(e->raw, o);
            uint64_t r_info   = rd64(e->raw, o+8);
            uint32_t type = (uint32_t)(r_info & 0xffffffff);
            uint32_t sidx = (uint32_t)(r_info >> 32);
            if(!r_offset || type != 1026) continue;
            const char *nm = symname(e, (int)sidx);
            VLOG("    JUMP_SLOT off=0x%llx sym=%u name='%s'\n",
                (unsigned long long)r_offset, sidx, nm);
            uint64_t val = relocated_symbol(e,sidx);
            uc_mem_write(e->uc, r_offset+e->load_bias, &val, 8);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* context generators (structural discovery)                           */

/* prologue: stp x29,x30,[sp,#-0x20]! ; str x28,[sp,#0x10] ; mov x29,sp ;
 *           sub sp,sp,#imm12,lsl#12 (0x9000-class frame) */
#define SIG_W0 0xA9BE7BFDu
#define SIG_W1 0xF9000BFCu
#define SIG_W2 0x910003FDu

static int is_bigframe(uint32_t w){
    return (w & 0xFFC003FFu) == 0xD14003FFu;      /* sub sp, sp, #imm12, lsl #12 */
}

static int gen_discover(const emu_t *e, const region_t *regs, int nregs,
                        uint64_t *out, int max){
    int n = 0; (void)e;
    for(int r = 0; r < nregs && n < max; r++){
        if(regs[r].len < 16) continue;
        const uint8_t *d = regs[r].data;
        for(size_t off = 0; off + 16 <= regs[r].len; off += 4){
            uint32_t w0, w1, w2, w3;
            memcpy(&w0, d+off, 4); memcpy(&w1, d+off+4, 4);
            memcpy(&w2, d+off+8, 4); memcpy(&w3, d+off+12, 4);
            if(w0 == SIG_W0 && w1 == SIG_W1 && w2 == SIG_W2 && is_bigframe(w3))
                if(n < max) out[n++] = regs[r].va + (uint64_t)off;
        }
    }
    return n;
}

static int gen_run(emu_t *e, uint64_t entry){
    int before = e->ncaptures;
    for(int c = before; c < 16; c++) e->capture_entry[c] = entry;
    setup_regs(e->uc, entry, SENT_CTOR, 0, STACK_TOP - 0x200000, MISC_BASE + 0x500000);
    uc_err rc = uc_emu_start(e->uc, entry, 0, 0, 4000000ULL);
    if(rc && rc != UC_ERR_OK && rc != UC_ERR_FETCH_UNMAPPED){
        uint64_t pc = rdreg(e->uc, R_PC);
        VLOG("    [gen 0x%llx] stopped: %s at pc=0x%llx\n",
             (unsigned long long)entry, uc_strerror(rc), (unsigned long long)pc);
    }
    return e->ncaptures > before;
}

/* plausibility: every 0x400-aligned table after the 0x170 header holds
 * 256 distinct uint32 values */
static int ctx_plausible(const uint8_t *b, int size){
    if(size < 0x170 + 0x400) return 0;
    int ntab = (size - 0x170) / 0x400;
    if(ntab < 1) return 0;
    for(int t = 0; t < ntab; t++){
        const uint8_t *tab = b + 0x170 + (size_t)t*0x400;
        uint32_t seen[256];
        for(int i = 0; i < 256; i++){
            uint32_t v; memcpy(&v, tab + (size_t)i*4, 4);
            for(int j = 0; j < i; j++)
                if(seen[j] == v) return 0;
            seen[i] = v;
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* top level                                                           */

static void emu_free(emu_t *e){
    for(int i=0;i<16;i++)if(e->inflaters[i].active)inflateEnd(&e->inflaters[i].stream);
    if(e->uc){ uc_close(e->uc); e->uc = NULL; }
    for(int i = 0; i < e->nfiles; i++) free(e->files[i].content);
    free(e->fake_so);
    for(int i = 0; i < e->nth; i++){
        fork_mem_free(e->th[i].fork_mem, e->th[i].nfork_mem);
        if(e->th[i].cpu) uc_context_free(e->th[i].cpu);
    }
    /* symnames/raw are owned by the caller */
}

/* run the full offline pipeline; writes ctx_<n>.bin files into outdir.
 * returns number of candidates written, or < 0 on error. */
int ctxgen_run(const char *so_path, const char *outdir, int verbose){
    g_verbose = verbose;
    if(mkdir(outdir,0755) && errno!=EEXIST){
        fprintf(stderr,"error: cannot create context directory: %s\n",outdir);
        return -1;
    }
    emu_t A; memset(&A, 0, sizeof A);
    A.image_name=strrchr(so_path,'/');A.image_name=A.image_name?A.image_name+1:so_path;
    FILE *f = fopen(so_path, "rb");
    if(!f){ fprintf(stderr, "error: cannot open %s\n", so_path); return -1; }
    fseek(f, 0, SEEK_END); long szl = ftell(f); fseek(f, 0, SEEK_SET);
    if(szl <= 0){ fclose(f); return -1; }
    A.raw = (uint8_t *)malloc((size_t)szl);
    if(fread(A.raw, 1, (size_t)szl, f) != (size_t)szl){ fclose(f); free(A.raw); return -1; }
    fclose(f);
    A.raw_len = (size_t)szl;

    if(elf_load(&A) < 0){
        fprintf(stderr, "error: not a loadable AArch64 ELF: %s\n", so_path);
        free(A.raw);
        return -1;
    }
    elf_syms(&A);

    /* ---- session A: run ctor + JNI, then diff the executable segment ---- */
    uc_err rc = uc_open(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, &A.uc);
    if(rc){
        fprintf(stderr, "error: uc_open failed (%s)\n", uc_strerror(rc));
        return -1;
    }
    if(emu_map(&A) < 0 || apply_relocations(&A) < 0){
        fprintf(stderr, "error: mapping/relocation failed\n");
        emu_free(&A); free(A.raw);
        return -1;
    }
    VLOG("[*] stubs after relocation: %d\n", A.nstubs);
    for(int i = 0; i < A.nstubs && i < 8; i++)
        VLOG("     stub[%d] 0x%llx %s\n", i, (unsigned long long)A.stubs[i].addr, A.stubs[i].name);
    uint64_t tls = TLS_BASE;
    uc_reg_write(A.uc, UC_ARM64_REG_TPIDR_EL0, &tls);
    uint64_t canary = 0x1122334455667788ULL;
    uc_mem_write(A.uc, TLS_BASE + 0x28, &canary, 8);
    A.heap_next = HEAP_BASE + 0x1000;
    A.mmap_next = MMAP_BASE;
    A.errno_addr = MISC_BASE + 0x1000;
    A.next_fd = 0x200;
    A.file_next = MISC_BASE + 0x4000;

    seg_t *segx = NULL;
    for(int i = 0; i < A.nsegs; i++)
        if(A.segs[i].flags & 4){ segx = &A.segs[i]; break; }
    if(!segx){
        fprintf(stderr, "error: no executable segment\n");
        emu_free(&A); free(A.raw);
        return -1;
    }
    uint8_t *snap = (uint8_t *)malloc((size_t)segx->filesz);
    uc_mem_read(A.uc, segx->va, snap, segx->filesz);

    fprintf(stderr, "[*] emulating startup (ctor + JNI_OnLoad) of %s\n", so_path);
    if(run_unpack(&A) < 0){
        fprintf(stderr, "error: startup emulation failed\n");
        emu_free(&A); free(snap); free(A.raw);
        return -1;
    }
    fprintf(stderr, "[*] startup complete (%llu instructions)\n",
            (unsigned long long)A.insn_count);

    /* diff: changed runs in the executable segment */
    uint8_t *after = (uint8_t *)malloc((size_t)segx->filesz);
    uc_mem_read(A.uc, segx->va, after, segx->filesz);
    uint64_t starts[MAX_REGIONS], ends[MAX_REGIONS]; int nr = 0;
    {
        size_t i = 0;
        while(i < segx->filesz){
            if(snap[i] != after[i]){
                size_t j = i;
                while(j < segx->filesz && snap[j] != after[j]) j++;
                /* coalesce runs separated by < 64 KiB: the constructor patches
                 * many small spots inside the big decrypted span */
                if(nr > 0 && (uint64_t)i - ends[nr-1] < 0x10000){
                    ends[nr-1] = (uint64_t)j;
                } else if(nr < MAX_REGIONS){
                    starts[nr] = (uint64_t)i; ends[nr] = (uint64_t)j; nr++;
                } else {
                    ends[MAX_REGIONS-1] = (uint64_t)j;
                }
                i = j;
            } else i++;
        }
    }
    VLOG("[*] changed runs (coalesced): %d\n", nr);
    free(snap);
    /* extract current bytes for the changed runs (reads from session-A memory,
     * so gaps between changes carry the true image bytes) */
    region_t regs[MAX_REGIONS]; int nregs = 0;
    uint64_t total_changed = 0;
    for(int r = 0; r < nr && nregs < MAX_REGIONS; r++){
        region_t *g = &regs[nregs++];
        g->va = segx->va + starts[r];
        g->len = (size_t)(ends[r] - starts[r]);
        g->data = (uint8_t *)malloc(g->len);
        uc_mem_read(A.uc, g->va, g->data, g->len);
        total_changed += g->len;
        if(g->len > (size_t)0xffffffffULL) g->len = 0xfffff000;
    }
    free(after);
    fprintf(stderr, "[*] decrypted regions: %d (%llu bytes)\n", nregs,
            (unsigned long long)total_changed);
    if(!total_changed){
        fprintf(stderr, "error: constructor decrypted nothing\n");
        for(int r = 0; r < nregs; r++) free(regs[r].data);
        emu_free(&A); free(A.raw);
        return -1;
    }

    /* save artifacts (these replace text_driver_dec.bin / region_*.bin) */
    for(int r = 0; r < nregs; r++){
        char path[512];
        snprintf(path, sizeof path, "%s/dec_%llx_%zx.bin", outdir,
                 (unsigned long long)regs[r].va, regs[r].len);
        FILE *o = fopen(path, "wb");
        if(o){ fwrite(regs[r].data, 1, regs[r].len, o); fclose(o); }
    }

    /* ---- session B: fresh image + decrypted regions -> run generators ---- */
    emu_t B; memset(&B, 0, sizeof B);
    B.image_name=A.image_name;
    B.raw = A.raw; B.raw_len = A.raw_len;
    B.nsegs = A.nsegs;
    for(int s = 0; s < A.nsegs; s++) B.segs[s] = A.segs[s];
    rc = uc_open(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, &B.uc);
    if(rc){
        fprintf(stderr, "error: uc_open (session B)\n");
        for(int r = 0; r < nregs; r++) free(regs[r].data);
        emu_free(&A); free(A.raw);
        return -1;
    }
    elf_syms(&B);
    if(emu_map(&B) < 0 || apply_relocations(&B) < 0){
        fprintf(stderr, "error: session B mapping\n");
        for(int r = 0; r < nregs; r++) free(regs[r].data);
        emu_free(&A); free(A.raw);
        return -1;
    }
    uc_reg_write(B.uc, UC_ARM64_REG_TPIDR_EL0, &tls);
    uc_mem_write(B.uc, TLS_BASE + 0x28, &canary, 8);
    B.heap_next = HEAP_BASE + 0x1000;
    B.mmap_next = MMAP_BASE;
    B.errno_addr = MISC_BASE + 0x1000;
    B.next_fd = 0x200;
    B.file_next = MISC_BASE + 0x4000;
    for(int r = 0; r < nregs; r++)
        uc_mem_write(B.uc, regs[r].va, regs[r].data, regs[r].len);

    uint64_t entries[64];
    int nentries = gen_discover(&B, regs, nregs, entries, 64);
    fprintf(stderr, "[*] generator prologue candidates: %d\n", nentries);

    uc_hook hgen, hintr2;
    uc_hook_add(B.uc, &hgen, UC_HOOK_CODE, hook_code_gen, &B, 1, 0);
    uc_hook_add(B.uc, &hintr2, UC_HOOK_INTR, hook_intr, &B, 1, 0);
    for(int k = 0; k < nentries; k++){
        fprintf(stderr, "[*] running generator entry 0x%llx ...\n",
                (unsigned long long)entries[k]);
        gen_run(&B, entries[k]);
    }

    /* ---- write captures ---- */
    int written = 0;
    for(int c = 0; c < B.ncaptures; c++){
        if(!ctx_plausible(B.captures[c], (int)B.capture_size[c])){
            fprintf(stderr, "[!] capture at site 0x%llx failed the table filter; skipped\n",
                    (unsigned long long)B.capture_site[c]);
            free(B.captures[c]);
            continue;
        }
        char path[512];
        snprintf(path, sizeof path, "%s/ctx_%llx_%d.bin", outdir,
                 (unsigned long long)B.capture_entry[c], written);
        FILE *o = fopen(path, "wb");
        if(o){
            fwrite(B.captures[c], 1, B.capture_size[c], o);
            fclose(o);
            fprintf(stderr, "[+] context candidate: %s (entry 0x%llx, copy site 0x%llx)\n",
                    path, (unsigned long long)B.capture_entry[c],
                    (unsigned long long)B.capture_site[c]);
            written++;
        }
        free(B.captures[c]);
    }
    fprintf(stderr, "[*] %d context candidate(s) written to %s\n", written, outdir);

    emu_free(&B);
    if(B.symnames){
        for(int i = 0; i < B.nsyms; i++) free(B.symnames[i]);
        free(B.symnames);
    }
    for(int r = 0; r < nregs; r++) free(regs[r].data);
    emu_free(&A);
    if(A.symnames){
        for(int i = 0; i < A.nsyms; i++) free(A.symnames[i]);
        free(A.symnames);
    }
    free(A.raw);
    return written;
}

#include "native_impl.h"
