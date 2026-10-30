/* main.c -- command line front-end for the LBTS tool.
 *
 *   lbts decrypt <input.dat> [output] [--context context.bin] [--json config.json]
 *   lbts encrypt <input>      [output.dat]
 *   lbts info    <input.dat>
 *   lbts scan    <supercell_brawlstars.so>
 */
#define _POSIX_C_SOURCE 200809L
#include "lbts.h"
#include "promon.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_UNICORN
int ctxgen_run(const char *so_path, const char *outdir, int verbose);
int ctxgen_native_unpack(const char *game,const char *shield,const char *apk,const char *outdir,int verbose);
int ctxgen_strings(const char *shield,const char *apk,const char *owner,uint32_t registration,const char *ids,const char *output);
#endif

/* ---- auto-locate the game .so next to the .dat ---- */
static const char *SO_NAMES[] = {
    "supercell_brawlstars.so",
    "libsupercell_brawlstars.so",
    "libsupercell_clashofclans.so",
    "libsupercell_clashroyale.so",
    "libsupercell_moco.so",
    "libsupercell_squad.so",
    "libsupercell_hayday.so",
    "libsupercell_boombeach.so",
    NULL
};

static int load_so(const char *explicit_path, uint8_t **buf, size_t *n, const char **used){
    const char *cands[sizeof SO_NAMES / sizeof SO_NAMES[0] + 1]; int k=0;
    if(explicit_path) cands[k++]=explicit_path;
    if(!explicit_path) for(int i=0;SO_NAMES[i];i++) cands[k++]=SO_NAMES[i];
    for(int i=0;i<k;i++){
        FILE *f=fopen(cands[i],"rb");
        if(!f) continue;
        fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
        if(sz<0){ fclose(f); continue; }
        uint8_t *b=(uint8_t*)malloc((size_t)sz+1);
        if(!b){ fclose(f); continue; }
        if(sz>0 && fread(b,1,(size_t)sz,f)!=(size_t)sz){ free(b); fclose(f); continue; }
        fclose(f);
        *buf=b; *n=(size_t)sz; *used=cands[i];
        return 0;
    }
    return -1;
}

/* ---- counters for `info` ---- */
static long g_msgs=0, g_envcand=0;
static void count_messages(const uint8_t *p, size_t size, int depth){
    if(size==0||depth>12) return;
    const uint8_t *cur=p,*end=p+size; struct pb_field f;
    while(cur<end){
        if(pb_next(&cur,end,&f)<0) break;
        if(f.wire!=2) continue;
        if(env_is_size(f.size) && !pb_is_message(f.data,f.size)) continue; /* envelope leaf */
        if(pb_is_message(f.data,f.size)){ g_msgs++; count_messages(f.data,f.size,depth+1); }
    }
}
static int cb_count(const struct envelope *e, void *ud){ (void)e; (void)ud; g_envcand++; return 0; }

/* ---- supported decrypt path: collect + generically decode plaintext ---- */
struct plain_blob { uint8_t *data; size_t len; long env; };
static struct plain_blob *g_plain=NULL;
static size_t g_nplain=0, g_plain_cap=0;
static int g_keep_plain;

static void plain_free(void){
    for(size_t i=0;i<g_nplain;i++) free(g_plain[i].data);
    free(g_plain); g_plain=NULL; g_nplain=g_plain_cap=0;
}

struct dec_ctx { FILE *out; struct whitebox *wb; const uint8_t *hdr; size_t hdr_len; long auth, dec, failed; };

/* Collect the first few envelopes: they are the decryption probes used to pick
 * the correct white-box context. */
#define PROBE_MAX 8
struct probe_ctx { struct envelope e[PROBE_MAX]; int n; };
static int cb_probe(const struct envelope *e, void *ud){
    struct probe_ctx *p=(struct probe_ctx*)ud;
    if(p->n >= PROBE_MAX) return 1;
    p->e[p->n++] = *e;
    return 0;
}

static int cb_decrypt(const struct envelope *e, void *ud){
    struct dec_ctx *c=(struct dec_ctx*)ud;
    if(e->iv==c->hdr && e->ct_len+48==c->hdr_len) return 0;
    uint8_t tag[32];
    int ar = wb_auth_verify(c->wb->context, c->wb->context_size,
                            e->iv, e->ct, e->ct_len, e->auth, c->hdr, tag);
    if(ar==WB_AUTH_UNSUPPORTED){ c->failed++; return 0; }
    if(ar!=WB_AUTH_OK){ c->failed++; return 0; }  /* never accept bad auth */
    c->auth++;
    uint8_t *buf=(uint8_t*)malloc(e->ct_len?e->ct_len:1);
    if(!buf){ c->failed++; return 0; }
    int n = wb_cbc_decrypt_block(c->wb->context, c->wb->context_size,
                                 e->iv, e->ct, e->ct_len, buf);
    if(n<0){ free(buf); c->failed++; return 0; }
    c->dec++;
    if(g_nplain==g_plain_cap){
        size_t cap=g_plain_cap ? g_plain_cap*2 : 16;
        if(cap<g_plain_cap || cap>SIZE_MAX/sizeof(*g_plain)){ free(buf); return 1; }
        struct plain_blob *p=(struct plain_blob*)realloc(g_plain,cap*sizeof(*g_plain));
        if(!p){ free(buf); return 1; }
        g_plain=p; g_plain_cap=cap;
    }
    g_plain[g_nplain].data=buf; g_plain[g_nplain].len=(size_t)n; g_plain[g_nplain].env=(long)g_nplain;
    g_nplain++;
    return 0;
}

static int printable(const uint8_t *p, size_t n){
    if(n==0) return 0;
    size_t pr=0; for(size_t i=0;i<n;i++){ uint8_t c=p[i]; if(c==9||c==10||c==13||(c>=32&&c<127)) pr++; }
    return pr*100 >= n*85; /* >=85% printable */
}

static void dump_message(const uint8_t *p, size_t size, FILE *out, const char *indent, int depth);

static void dump_field_value(const struct pb_field *f, FILE *out, const char *indent, int depth){
    if(f->wire==2){
        if(printable(f->data,f->size)){
            fprintf(out,"%s  field %u str = \"", indent, f->number);
            for(size_t i=0;i<f->size;i++){ uint8_t c=f->data[i]; fputc((c>=32&&c<127)?c:'.', out); }
            fprintf(out,"\"\n");
        } else if(depth<5 && pb_is_message(f->data,f->size)){
            fprintf(out,"%s  field %u msg:\n", indent, f->number);
            dump_message(f->data,f->size,out,indent,depth+1);
        } else {
            fprintf(out,"%s  field %u bytes[%zu]\n", indent, f->number, f->size);
        }
    } else if(f->wire==0){
        fprintf(out,"%s  field %u varint = %llu\n", indent, f->number,(unsigned long long)f->value);
    } else if(f->wire==1){
        uint64_t v=0; for(int i=0;i<8;i++) v|=(uint64_t)f->data[i]<<(8*i);
        fprintf(out,"%s  field %u i64 = %llu\n", indent, f->number,(unsigned long long)v);
    } else if(f->wire==5){
        uint32_t v=(uint32_t)f->data[0]|((uint32_t)f->data[1]<<8)|((uint32_t)f->data[2]<<16)|((uint32_t)f->data[3]<<24);
        fprintf(out,"%s  field %u i32 = %u\n", indent, f->number, v);
    }
}

static void dump_message(const uint8_t *p, size_t size, FILE *out, const char *indent, int depth){
    const uint8_t *cur=p,*end=p+size; struct pb_field f;
    while(cur<end){
        if(pb_next(&cur,end,&f)<0) break;
        dump_field_value(&f,out,indent,depth);
    }
}

/* Generic, schema-agnostic decode of all decrypted envelope plaintexts:
 * each plaintext is itself a protobuf message; we print its strings and
 * static fields. The exact Jigsaw field numbering is not assumed. */
static int dump_decoded(const uint8_t *ctx, size_t ctx_len, FILE *out){
    (void)ctx;(void)ctx_len;
    if(g_nplain==0) return 0;
    fprintf(out,"\nfields/values\n=============\n");
    for(size_t i=0;i<g_nplain;i++){
        fprintf(out,"\n[envelope %ld] (%zu bytes)\n", g_plain[i].env, g_plain[i].len);
        if(pb_is_message(g_plain[i].data,g_plain[i].len))
            dump_message(g_plain[i].data, g_plain[i].len, out, "", 0);
        else if(printable(g_plain[i].data,g_plain[i].len)){
            fprintf(out,"  text = \"");
            for(size_t j=0;j<g_plain[i].len;j++){
                uint8_t ch=g_plain[i].data[j];
                if(ch=='"' || ch=='\\') fputc('\\',out);
                if(ch>=32 && ch<127) fputc(ch,out);
                else fprintf(out,"\\x%02x",ch);
            }
            fprintf(out,"\"\n");
        } else fprintf(out,"  binary plaintext[%zu]\n",g_plain[i].len);
    }
    return 1;
}


/* ---------- schema-agnostic JSON export of the Promon field config ----------
 * Each decrypted envelope is a protobuf message containing repeated entries:
 *
 *   field 1: entry {
 *     field 1: field-name (string)
 *     field 2: value {
 *       field 1: bool   (varint 0/1)
 *       field 5: int    (sint32 / protobuf zigzag)
 *       field 9: string (length-delimited)
 *     }
 *   }
 *
 * The export keeps the envelope grouping and field names; class names are not
 * stored in the config, so the dex patcher matches these groups against the
 * smali classes it is patching.  No value is guessed: unrecognised shapes are
 * skipped and reported by their absence.
 */
static void json_string(FILE *out, const uint8_t *p, size_t n){
    fputc('"',out);
    for(size_t i=0;i<n;i++){
        uint8_t c=p[i];
        switch(c){
        case '"': fputs("\\\"",out); break;
        case '\\': fputs("\\\\",out); break;
        case '\b': fputs("\\b",out); break;
        case '\f': fputs("\\f",out); break;
        case '\n': fputs("\\n",out); break;
        case '\r': fputs("\\r",out); break;
        case '\t': fputs("\\t",out); break;
        default:
            if(c<0x20 || c==0x7f) fprintf(out,"\\u%04x",(unsigned)c);
            else fputc(c,out);
        }
    }
    fputc('"',out);
}

struct json_entry { const uint8_t *name; size_t name_len; int type; uint64_t value; const uint8_t *str; size_t str_len; };

static int parse_json_entry(const uint8_t *p, size_t size, struct json_entry *e){
    const uint8_t *cur=p,*end=p+size; struct pb_field f;
    memset(e,0,sizeof(*e));
    while(cur<end){
        if(pb_next(&cur,end,&f)<0) return -1;
        if(f.number==1 && f.wire==2 && !e->name){ e->name=f.data; e->name_len=f.size; }
        else if(f.number==2 && f.wire==2){
            const uint8_t *vc=f.data,*ve=f.data+f.size; struct pb_field v;
            while(vc<ve){
                if(pb_next(&vc,ve,&v)<0) break;
                if(v.number==1 && v.wire==0 && !e->type){ e->type='Z'; e->value=v.value; break; }
                if(v.number==5 && v.wire==0 && !e->type){
                    /* sint32: protobuf zigzag encoding, not raw two's complement */
                    e->type='I';
                    e->value=(v.value>>1) ^ (uint64_t)-(int64_t)(v.value&1);
                    break;
                }
                if(v.number==9 && v.wire==2 && !e->type){ e->type='S'; e->str=v.data; e->str_len=v.size; break; }
            }
        }
    }
    return e->name && e->type ? 0 : -1;
}

/* A string group is a message whose children are all
 *
 *   field 1: entry { field 2: value { field 9: string } }
 *
 * Unlike a field-group entry there is no field-1 name inside the entry.  The
 * groups appear in class order and their slots concatenate to the native
 * getString() index space (id 0 .. N-1), which is why the order below is the
 * index order and must not be sorted.
 */
static int string_entry(const uint8_t *p, size_t size, const uint8_t **str, size_t *len){
    const uint8_t *cur=p,*end=p+size; struct pb_field f;
    const uint8_t *value=NULL; size_t value_len=0;
    int has_name=0;
    while(cur<end){
        if(pb_next(&cur,end,&f)<0) return -1;
        if(f.number==1 && f.wire==2) has_name=1;
        else if(f.number==2 && f.wire==2){ value=f.data; value_len=f.size; }
    }
    if(has_name || !value) return -1;
    cur=value; end=value+value_len;
    while(cur<end){
        if(pb_next(&cur,end,&f)<0) return -1;
        if(f.number==9 && f.wire==2){ *str=f.data; *len=f.size; return 0; }
    }
    return -1;
}

static int is_string_group(const uint8_t *p, size_t size){
    const uint8_t *cur=p,*end=p+size; struct pb_field f;
    int entries=0;
    while(cur<end){
        if(pb_next(&cur,end,&f)<0) return 0;
        if(f.number!=1 || f.wire!=2) return 0;
        const uint8_t *str; size_t len;
        if(string_entry(f.data,f.size,&str,&len)<0) return 0;
        entries++;
    }
    return entries>0;
}

static void dump_string_group(FILE *out, const uint8_t *p, size_t size, int *first){
    const uint8_t *cur=p,*end=p+size; struct pb_field f;
    while(cur<end){
        if(pb_next(&cur,end,&f)<0) break;
        const uint8_t *str; size_t len;
        if(f.number!=1 || f.wire!=2) continue;
        if(string_entry(f.data,f.size,&str,&len)<0) continue;
        if(!*first) fputc(',',out);
        *first=0;
        fputc('\n',out);
        fputs("    ",out);
        json_string(out,str,len);
    }
}

static int export_json(const char *path){
    FILE *out=fopen(path,"wb");
    if(!out){ fprintf(stderr,"error: cannot open %s\n",path); return -1; }
    fputs("{\n  \"format\": \"lbts-config\",\n  \"version\": 1,\n  \"strings\": [",out);
    int first_string=1;
    for(size_t i=0;i<g_nplain;i++){
        if(is_string_group(g_plain[i].data,g_plain[i].len))
            dump_string_group(out,g_plain[i].data,g_plain[i].len,&first_string);
    }
    fputs("\n  ],\n  \"envelopes\": [\n",out);
    int first=1;
    for(size_t i=0;i<g_nplain;i++){
        const uint8_t *p=g_plain[i].data,*end=p+g_plain[i].len; struct pb_field f;
        size_t count=0;
        /* dry run to skip envelopes with no field entries */
        const uint8_t *q=p;
        while(q<end){
            if(pb_next(&q,end,&f)<0) break;
            if(f.number==1 && f.wire==2){ struct json_entry e; if(parse_json_entry(f.data,f.size,&e)==0) count++; }
        }
        if(!count) continue;
        if(!first) fputs(",\n",out);
        first=0;
        fprintf(out,"    {\"id\": %ld, \"fields\": [",g_plain[i].env);
        int first_field=1;
        const uint8_t *cur=p;
        while(cur<end){
            if(pb_next(&cur,end,&f)<0) break;
            if(f.number!=1 || f.wire!=2) continue;
            struct json_entry e;
            if(parse_json_entry(f.data,f.size,&e)<0) continue;
            if(!first_field) fputc(',',out);
            first_field=0;
            fputs("\n      {\"name\": ",out); json_string(out,e.name,e.name_len);
            if(e.type=='S'){
                fputs(", \"type\": \"Ljava/lang/String;\", \"value\": ",out);
                json_string(out,e.str,e.str_len);
            } else if(e.type=='Z'){
                fprintf(out,", \"type\": \"Z\", \"value\": %s",e.value ? "true" : "false");
            } else {
                fprintf(out,", \"type\": \"I\", \"value\": %lld",(long long)e.value);
            }
            fputc('}',out);
        }
        fputs("\n    ]}",out);
    }
    fputs("\n  ]\n}\n",out);
    fclose(out);
    return 0;
}

static int patch_config(struct promon_config *c){
    memset(c, 0, sizeof *c);
    for(size_t i=0;i<g_nplain;i++){
        const uint8_t *p=g_plain[i].data, *end=p+g_plain[i].len;
        struct pb_field f;
        if(is_string_group(p,g_plain[i].len)){
            while(p<end && pb_next(&p,end,&f)==0){
                const uint8_t *text; size_t len;
                if(string_entry(f.data,f.size,&text,&len)) goto error;
                struct promon_text *a=realloc(c->strings,(c->nstrings+1)*sizeof(*a));
                if(!a) goto error;
                c->strings=a; c->strings[c->nstrings++]=(struct promon_text){text,len};
            }
        } else {
            struct promon_group g={0};
            while(p<end && pb_next(&p,end,&f)==0){
                struct json_entry e;
                if(f.number!=1 || f.wire!=2 || parse_json_entry(f.data,f.size,&e)) continue;
                struct promon_field *a=realloc(g.fields,(g.count+1)*sizeof(*a));
                if(!a){
                    for(size_t k=0;k<g.count;k++) free(g.fields[k].name);
                    free(g.fields); goto error;
                }
                g.fields=a;
                struct promon_field *v=&g.fields[g.count++];
                v->name=malloc(e.name_len+1);
                if(!v->name){
                    for(size_t k=0;k<g.count;k++) free(g.fields[k].name);
                    free(g.fields); goto error;
                }
                memcpy(v->name,e.name,e.name_len); v->name[e.name_len]=0;
                v->type=e.type; v->value=(int64_t)e.value;
                v->text=(struct promon_text){e.str,e.str_len};
            }
            if(g.count){
                struct promon_group *a=realloc(c->groups,(c->ngroups+1)*sizeof(*a));
                if(!a){
                    for(size_t k=0;k<g.count;k++) free(g.fields[k].name);
                    free(g.fields); goto error;
                }
                c->groups=a; c->groups[c->ngroups++]=g;
            } else free(g.fields);
        }
    }
    return 0;
error:
    promon_config_free(c); return -1;
}

/* ================================ info =============================== */
static int cmd_info(const char *path){
    struct lbts L;
    if(lbts_parse_file(&L,path)<0){ fprintf(stderr,"error: not an LBTS file: %s\n",path); return 2; }

    printf("LBTS detected: yes\n");
    printf("file size: %zu bytes\n", L.raw_size);
    printf("chunks: %d\n", L.count);
    for(int i=0;i<L.count;i++)
        printf("  chunk 0x%02x: %u bytes (data at +?)\n", L.chunks[i].type, L.chunks[i].size);

    const struct lbts_chunk *c30 = lbts_find(&L,0x30);
    if(!c30){ printf("chunk 0x30: (absent)\n"); lbts_free(&L); return 0; }

    /* summarize top-level protobuf of chunk 0x30 */
    printf("\nchunk 0x30 protobuf\n");
    const uint8_t *cur=c30->data,*end=c30->data+c30->size; struct pb_field f;
    while(cur<end){
        if(pb_next(&cur,end,&f)<0){ printf("  (malformed tail)\n"); break; }
        if(f.wire==2){
            const char *kind = pb_is_message(f.data,f.size) ? "message" :
                               (env_is_size(f.size) ? "envelope-sized blob" : "bytes");
            printf("  field %u wire=%u len=%zu -> %s\n", f.number,f.wire,f.size,kind);
        } else {
            printf("  field %u wire=%u value=%llu\n", f.number,f.wire,(unsigned long long)f.value);
        }
    }

    g_msgs=0; g_envcand=0;
    count_messages(c30->data,c30->size,0);
    env_walk(c30->data,c30->size,cb_count,NULL);

    printf("\nnested messages: %ld\n", g_msgs);
    printf("candidate envelopes: %ld\n", g_envcand);
    lbts_free(&L);
    return 0;
}

/* ================================ scan =============================== */
static int cmd_scan(int argc, char **argv){
    if(argc<3){ fprintf(stderr,"usage: 8nomorp scan <shield.so>\n"); return 2; }
    FILE *f=fopen(argv[2],"rb");
    if(!f){ fprintf(stderr,"error: cannot open %s\n",argv[2]); return 2; }
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    uint8_t *b=(uint8_t*)malloc((size_t)sz+1);
    if(sz>0 && fread(b,1,(size_t)sz,f)!=(size_t)sz){ fclose(f); free(b); return 2; }
    fclose(f);

    printf("[scanning %s]\n",argv[2]);
    wb_report(b,(size_t)sz,stdout);

    if(strstr(argv[2],".so")==NULL){ /* ok, still fine */ }
    free(b);
    return 0;
}

/* ============================== decrypt ============================== */
#ifdef WITH_UNICORN
static int load_generated_candidates(const char *dir, struct whitebox *wb){
    /* ctxgen wrote ctx_<entry>_<n>.bin candidates: load them all */
    int n = 0;
    DIR *d = opendir(dir);
    if(!d) return 0;
    struct dirent *de;
    while((de = readdir(d))){
        if(strncmp(de->d_name, "ctx_", 4)) continue;
        char full[1024];
        snprintf(full, sizeof full, "%s/%s", dir, de->d_name);
        FILE *f = fopen(full, "rb");
        if(!f) continue;
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
        if(sz <= 0 || sz > 1048576){ fclose(f); continue; }
        if(wb->context_size && (size_t)sz!=wb->context_size){ fclose(f); continue; }
        uint8_t *b = (uint8_t *)malloc((size_t)sz);
        if(!b || fread(b, 1, (size_t)sz, f) != (size_t)sz){ free(b); fclose(f); continue; }
        fclose(f);
        if(wb->ncand < WB_MAX_CANDIDATES){
            wb->context_size=(size_t)sz;
            wb->cand[wb->ncand] = b;
            wb->cand_va[wb->ncand] = -1;    /* runtime-generated */
            wb->ncand++;
            n++;
        } else free(b);
    }
    closedir(d);
    return n;
}
#endif

static int cmd_context(int argc, char **argv){
#ifndef WITH_UNICORN
    (void)argc; (void)argv;
    fprintf(stderr,"error: this build has no emulator; rebuild with `make unicorn all`\n");
    return 2;
#else
    if(argc < 3){
        fprintf(stderr,"usage: 8nomorp context <shield.so> [outdir]\n");
        return 2;
    }
    const char *so = argv[2];
    const char *outdir = argc > 3 ? argv[3] : "ctxgen";
    int n = ctxgen_run(so, outdir, getenv("CTXGEN_VERBOSE") != NULL);
    if(n < 0) return 3;
    printf("%d candidate context(s) in %s\n", n, outdir);
    return n ? 0 : 3;
#endif
}

static int cmd_decrypt(int argc, char **argv){
    if(argc<3){ fprintf(stderr,"usage: 8nomorp decrypt <input.dat> [output] [--context context.bin] [--json config.json] [--so shield.so]\n"); return 2; }
    const char *in = argv[2];
    const char *outpath = NULL, *ctxpath = NULL, *jsonpath = NULL, *sopath = NULL;
    for(int i=3;i<argc;i++){
        if(!strcmp(argv[i],"--context")){
            if(ctxpath || i+1>=argc){ fprintf(stderr,"error: --context requires one file\n"); return 2; }
            ctxpath=argv[++i];
        } else if(!strcmp(argv[i],"--json")){
            if(jsonpath || i+1>=argc){ fprintf(stderr,"error: --json requires one file\n"); return 2; }
            jsonpath=argv[++i];
        } else if(!strcmp(argv[i],"--so")){
            if(sopath || i+1>=argc){ fprintf(stderr,"error: --so requires one file\n"); return 2; }
            sopath=argv[++i];
        } else if(!outpath && argv[i][0]!='-') outpath=argv[i];
        else { fprintf(stderr,"error: unexpected argument: %s\n",argv[i]); return 2; }
    }
    uint8_t *provided_ctx=NULL; size_t provided_n=0;
    if(ctxpath){
        FILE *f=fopen(ctxpath,"rb");
        if(!f){ fprintf(stderr,"error: cannot open context: %s\n",ctxpath); return 2; }
        if(fseek(f,0,SEEK_END)){ fclose(f); return 2; }
        long n=ftell(f);
        if(n<=0 || n>1048576 || fseek(f,0,SEEK_SET)){ fclose(f); return 2; }
        provided_n=(size_t)n; provided_ctx=(uint8_t*)malloc(provided_n);
        if(!provided_ctx || fread(provided_ctx,1,provided_n,f)!=provided_n){
            fclose(f); free(provided_ctx); return 2;
        }
        fclose(f);
    }
    FILE *out = stdout;
    if(outpath){ out=fopen(outpath,"wb"); if(!out){ fprintf(stderr,"error: cannot open %s\n",outpath); free(provided_ctx); return 2; } }

    struct lbts L;
    if(lbts_parse_file(&L,in)<0){ fprintf(stderr,"error: not an LBTS file: %s\n",in); free(provided_ctx); if(out!=stdout)fclose(out); return 2; }

    const struct lbts_chunk *c30 = lbts_find(&L,0x30);

    fprintf(out,"LBTS\n====\n\n");
    fprintf(out,"file: %s\n",in);
    fprintf(out,"size: %zu bytes\n\n",L.raw_size);
    fprintf(out,"chunks\n");
    for(int i=0;i<L.count;i++)
        fprintf(out,"chunk 0x%02x: %u bytes\n",L.chunks[i].type,L.chunks[i].size);

    fprintf(out,"\ncrypto\n======\n");
    if(!c30){ fprintf(out,"no chunk 0x30 -> nothing to decrypt\n"); free(provided_ctx); lbts_free(&L); if(out!=stdout)fclose(out); return 0; }

    /* auto-load the game .so */
    uint8_t *so=NULL; size_t so_n=0; const char *used=NULL;
    int have_so = !ctxpath && (load_so(sopath,&so,&so_n,&used)==0);

    struct whitebox wb; memset(&wb,0,sizeof wb);
    wb.routine_va=wb.context_va=wb.context_file_off=-1;
    if(have_so) wb_scan(so,so_n,NULL,&wb);
    if(provided_ctx){
        /* Explicit input is never trusted: cb_decrypt authenticates each
         * envelope before decoding or emitting any of its plaintext. */
        wb.cand[0]=provided_ctx; wb.ncand=1;
        wb.context=provided_ctx; wb.context_size=provided_n;
        used=ctxpath;
        sha256(provided_ctx,provided_n,wb.ctx_sha);
        wb.ctx_sha_known=1;
    }

    fprintf(out,"whitebox: %s\n", ctxpath? "explicit context (authentication required)" : have_so? "found" : "no .so located");
    if(ctxpath) fprintf(out,"  context source: %s (%zu bytes)\n",ctxpath,provided_n);
    if(have_so){
        fprintf(out,"  source: %s\n", used);
        fprintf(out,"  packed executable: %s\n", wb.packed?"yes":"no");
        if(wb.context){
            char sha[65]; static const char*h="0123456789abcdef";
            for(int i=0;i<32;i++){sha[i*2]=h[wb.ctx_sha[i]>>4];sha[i*2+1]=h[wb.ctx_sha[i]&15];}sha[64]=0;
            fprintf(out,"  tables: %d x %zu x uint32 (context %zu bytes, table-0 off 0x%lx)\n",
                    wb.table_count,wb.table_entries,wb.context_size,(long)wb.context_file_off);
            fprintf(out,"  context sha-256: %s\n", sha);
        } else fprintf(out,"  context: not found\n");
    }

#ifdef WITH_UNICORN
    /* --so: generate the runtime white-box context from the packed .so
     * offline (emulates the protector's own startup), then let the
     * decryption-based selection pick whichever candidate authenticates. */
    if(!ctxpath && have_so && (sopath || !wb.context || wb.packed)){
        char ctxdir[512];
        const char *tmp=getenv("TMPDIR");
        if(!tmp || !*tmp) tmp="/tmp";
        if(snprintf(ctxdir,sizeof ctxdir,"%s/8nomorp-context-XXXXXX",tmp)>=(int)sizeof ctxdir){
            fprintf(stderr,"error: temporary directory path too long\n");
            lbts_free(&L); if(so)free(so); wb_free(&wb); if(out!=stdout)fclose(out); return 2;
        }
        if(!mkdtemp(ctxdir)){
            fprintf(stderr,"error: cannot create context directory\n");
            lbts_free(&L); if(so)free(so); wb_free(&wb);
            if(out!=stdout) fclose(out);
            return 2;
        }
        fprintf(stderr,"[*] generating white-box context from %s ...\n",used);
        int ng = ctxgen_run(used,ctxdir,getenv("CTXGEN_VERBOSE") != NULL);
        if(ng > 0){
            for(int i=0;i<wb.ncand;i++){ free(wb.cand[i]); wb.cand[i]=NULL; }
            wb.ncand=0; wb.context=NULL; wb.ctx_sha_known=0;
            int added = load_generated_candidates(ctxdir,&wb);
            /* runtime-generated tables take priority over static candidates */
            wb.context = NULL;
            fprintf(out,"  generation: %d runtime context candidate(s) from %s\n",added,used);
        } else {
            fprintf(stderr,"[!] context generation produced no candidates\n");
        }
        /* This directory belongs exclusively to this invocation. */
        DIR *d=opendir(ctxdir);
        if(d){
            struct dirent *de;
            while((de=readdir(d))){
                if(de->d_name[0]=='.') continue;
                char file[1024];
                if(snprintf(file,sizeof file,"%s/%s",ctxdir,de->d_name)<(int)sizeof file) unlink(file);
            }
            closedir(d); rmdir(ctxdir);
        }
    }
#endif

    /* enumerate envelopes */
    g_envcand=0;
    env_walk(c30->data,c30->size,cb_count,NULL);

    fprintf(out,"\ndecryption\n==========\n");
    fprintf(out,"envelope candidates: %ld\n",g_envcand);

    /* the top-level field 2 of chunk 0x30 is the format header blob */
    const uint8_t *hdr=NULL; size_t hdr_len=0;
    { const uint8_t *p=c30->data,*e=c30->data+c30->size; struct pb_field f;
      while(pb_next(&p,e,&f)==0){ if(f.number==2 && f.wire==2){ hdr=f.data; hdr_len=f.size; break; } } }

    /* Pick the correct white-box context by decryption (multiple structural
     * candidates are normal: the tables look like random data). */
    if(!wb.context && wb.ncand>0){
        struct probe_ctx pc; pc.n=0;
        env_walk(c30->data, c30->size, cb_probe, &pc);
        if(pc.n>0 && wb_select(&wb, pc.e, pc.n)==0)
            fprintf(out,"context: selected by decryption (va 0x%lx)\n", wb.context_va);
        else
            fprintf(out,"context: none of the %d candidates validates this container\n", wb.ncand);
    }

    if(wb.context){
        struct dec_ctx wctx = { out, &wb, hdr, hdr_len, 0, 0, 0 };
        env_walk(c30->data, c30->size, cb_decrypt, &wctx);

        fprintf(out,"authenticated: %ld\n", wctx.auth);
        fprintf(out,"decrypted: %ld\n", wctx.dec);
        if(wctx.failed) fprintf(out,"auth/padding failures: %ld\n", wctx.failed);
        fprintf(out,"authentication: %s\n", wctx.auth>0 ? "verified" : "n/a");

        if(g_keep_plain && wctx.failed){
            fprintf(stderr,"error: refusing to patch with incomplete authenticated config (%ld failures)\n",wctx.failed);
            lbts_free(&L); if(so)free(so); wb_free(&wb); if(out!=stdout)fclose(out);
            return 3;
        }

        if(wctx.dec>0){
            /* Only now, with validated plaintext, do we emit the decoded result. */
            if(jsonpath && export_json(jsonpath)<0){
                lbts_free(&L); if(so)free(so); wb_free(&wb);
                if(out!=stdout) fclose(out);
                return 2;
            }
            dump_decoded(wb.context, wb.context_size, out);
        } else {
            /* Crypto located but the recovered transform does not validate this
             * file: refuse rather than emit unverified plaintext. */
            fprintf(out,"\nUnsupported/new Promon white-box layout.\n");
            fprintf(out,"Unable to safely locate the crypto implementation.\n");
            fprintf(out,"\n(a context was located structurally in %s, but the recovered\n"
                        " transform did not produce authenticated plaintext for this file.)\n", used);
            lbts_free(&L); if(so)free(so); wb_free(&wb);
            if(out!=stdout) fclose(out);
            return 3;
        }
    } else {
        fprintf(out,"authenticated: n/a\n");
        fprintf(out,"decrypted: n/a\n");
        fprintf(out,"\nUnsupported/new Promon white-box layout.\n");
        fprintf(out,"Unable to safely locate the crypto implementation.\n");
        if(wb.ncand>0)
            fprintf(out,"\n(%d relocation-referenced context candidates were found in %s, but\n"
                        " none of them decrypts this container to a valid padding: the file\n"
                        " is bound to a runtime-produced context, not to any static table run.)\n",
                    wb.ncand, used);
        else
            fprintf(out,"\n(no relocation-referenced white-box context candidate exists in %s.)\n", used);
        lbts_free(&L); if(so)free(so); wb_free(&wb);
        if(out!=stdout) fclose(out);
        return 3;
    }

    if(!g_keep_plain) plain_free();
    lbts_free(&L); if(so)free(so); wb_free(&wb);
    if(out!=stdout) fclose(out);
    return 0;
}

/* ============================== encrypt ============================== */
static int cmd_patch(int argc, char **argv){
    if(argc<7){
        fprintf(stderr,"usage: 8nomorp %s <input.dat> <decoded-input> <new-output> --so <lib.so> | --context <context.bin>\n",argv[1]);
        return 2;
    }
    char **args=calloc((size_t)argc+1,sizeof(*args));
    if(!args) return 2;
    args[0]=argv[0]; args[1]="decrypt"; args[2]=argv[2]; args[3]="/dev/null";
    for(int i=5;i<argc;i++) args[i-1]=argv[i];
    g_keep_plain=1;
    int rc=cmd_decrypt(argc-1,args);
    g_keep_plain=0; free(args);
    if(rc){
        fprintf(stderr,"error: config decryption failed; run '8nomorp decrypt' for details\n");
        plain_free(); return rc;
    }
    struct promon_config config;
    if(patch_config(&config)){ plain_free(); return 2; }
    rc=promon_patch(argv[3],argv[4],&config);
    promon_config_free(&config); plain_free();
    return rc ? 3 : 0;
}

static int cmd_encrypt(int argc, char **argv){
    if(argc<3){ fprintf(stderr,"usage: 8nomorp encrypt <input> [output.dat]\n"); return 2; }
    (void)argv;
    /* Verification is recovered, but the inverse white-box transform needed
     * to construct ciphertext and encrypted tags is not proven. */
    fprintf(stderr,
        "Encryption is not implemented: the inverse white-box transform is not verified.\n");
    return 4;
}

int main(int argc, char **argv){
    int help=argc>=2&&(!strcmp(argv[1],"--help")||!strcmp(argv[1],"-h")||!strcmp(argv[1],"help"));
    if(argc<2 || help){
        FILE *out=help?stdout:stderr;
        fprintf(out,
            "8nomorp - offline LBTS, Java and ARM64 recovery tools\n\n"
            "Usage: 8nomorp COMMAND [arguments]\n\n"
            "  all      CONFIG DECODED OUTPUT --so SHIELD\n"
            "           Recover context and patch a decoded APK tree.\n"
            "  patch    CONFIG DECODED OUTPUT --context CONTEXT\n"
            "           Patch with an existing authenticated context.\n"
            "  unpack   LIBRARY SHIELD BASE_APK OUTPUT_DIR\n"
            "           Recover and verify supported ARM64 resolver calls.\n"
            "  context  SHIELD [OUTPUT_DIR]\n"
            "           Recover runtime context candidates.\n"
            "  decrypt  CONFIG [OUTPUT] [--context CONTEXT] [--so SHIELD] [--json JSON]\n"
            "  info     CONFIG\n"
            "  scan     SHIELD\n\n"
            "Output directories must not already exist.\n"
            "Set TMPDIR for temporary files; CTXGEN_VERBOSE=1 enables emulator diagnostics.\n"
            "Full APK workflow: python3 tools/build_apk.py --help\n"
            "Unsupported layouts fail closed. Encryption is not implemented.\n");
        return help?0:2;
    }
    if(!strcmp(argv[1],"decrypt")) return cmd_decrypt(argc,argv);
    if(!strcmp(argv[1],"context")) return cmd_context(argc,argv);
    if(!strcmp(argv[1],"strings")){
#ifdef WITH_UNICORN
        if(argc!=8){fprintf(stderr,"usage: 8nomorp strings SHIELD BASE CLASS REGISTRATION_ID IDS OUTPUT\n");return 2;}
        char *end;unsigned long id=strtoul(argv[5],&end,0);
        if(*end||id>UINT32_MAX)return 2;
        return ctxgen_strings(argv[2],argv[3],argv[4],(uint32_t)id,argv[6],argv[7])?1:0;
#else
        return 1;
#endif
    }
    if(!strcmp(argv[1],"unpack")){
        if(argc!=6){
            fprintf(stderr,"usage: 8nomorp unpack <libg.so> <shield.so> <base.apk> <new-output>\n");return 2;
        }
#ifdef WITH_UNICORN
        return ctxgen_native_unpack(argv[2],argv[3],argv[4],argv[5],getenv("CTXGEN_VERBOSE")!=NULL)?1:0;
#else
        fprintf(stderr,"error: native unpacking requires the Unicorn build\n");return 1;
#endif
    }
    if(!strcmp(argv[1],"patch") || !strcmp(argv[1],"all")) return cmd_patch(argc,argv);
    if(!strcmp(argv[1],"encrypt")) return cmd_encrypt(argc,argv);
    if(!strcmp(argv[1],"info"))    { if(argc<3) return 2; return cmd_info(argv[2]); }
    if(!strcmp(argv[1],"scan"))    return cmd_scan(argc,argv);
    fprintf(stderr,"error: unknown command '%s'\n",argv[1]);
    return 1;
}
