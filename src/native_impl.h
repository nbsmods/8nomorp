/* Internal native-unpack implementation; included once by ctxgen.c.
 * Instruction-pattern discovery, followed by ABI/coverage checks.
 * Recognized protector routines do not guarantee arbitrary new schemes. */
#ifndef NATIVE_IMPL_H
#define NATIVE_IMPL_H
#include "lbts.h"
#include <fcntl.h>
#include <unistd.h>

static int native_blob(const char *path,uint8_t **data,size_t *length){
    FILE *f=fopen(path,"rb");if(!f)return -1;
    long size;
    if(fseek(f,0,SEEK_END)||(size=ftell(f))<=0||(unsigned long)size>256u*1024*1024||fseek(f,0,SEEK_SET)){
        fclose(f);return -1;
    }
    uint8_t *b=malloc((size_t)size);if(!b){fclose(f);return -1;}
    if(fread(b,1,(size_t)size,f)!=(size_t)size){free(b);fclose(f);return -1;}
    fclose(f);*data=b;*length=(size_t)size;return 0;
}
static int native_executable(const emu_t *e,uint64_t address){
    for(int i=0;i<e->nsegs;i++){
        const seg_t *s=&e->segs[i];uint64_t start=e->load_bias+s->va;
        if((s->flags&1)&&address>=start&&address-start<s->filesz)return 1;
    }
    return 0;
}
static void native_environment_probe(uc_engine *uc,uint64_t pc,uint32_t size,void *ud){
    (void)pc;(void)size;(void)ud;
    /* Offline environment-only workaround. The enclosing initialization
     * routine is retained: it initializes the unpack engine. */
    wrreg(uc,R_X0,0);wrreg(uc,R_PC,rdreg(uc,R_X30));
}
/* Instruction signatures of narrow, previously audited environment probes.
 * These recognize relocated routines, NOT arbitrary future probes. No match
 * leaves initialization untouched; ambiguity fails. Never infer a bypass from
 * an initialization failure or skip the enclosing engine initializer. */
static const uint32_t native_probe_patterns[][16]={
    {0xd10203ff,0xa9027bfd,0xa9036ffc,0xa90467fa,0xa9055ff8,0xa90657f6,0xa9074ff4,0x910083fd,
     0x5286a029,0x528bef8a,0x7200005f,0x72abc349,0x72adc92a,0x529b1828,0x1a8a1129,0x72ac4228},
    {0xd101c3ff,0xa9017bfd,0xa9026ffc,0xa90367fa,0xa9045ff8,0xa90557f6,0xa9064ff4,0x910043fd,
     0x529281b8,0x529ff2da,0x528760b9,0x52822575,0x528a23bc,0x52881597,0x5292819b,0x529c5536},
    {0xd101c3ff,0xa9017bfd,0xa9026ffc,0xa90367fa,0xa9045ff8,0xa90557f6,0xa9064ff4,0x910043fd,
     0x52824495,0x528be5d7,0x52824479,0x5296175a,0x5291c85c,0x529a59f8,0x529a5a16,0x52937033}
};
#define NATIVE_PROBE_PATTERNS (sizeof native_probe_patterns/sizeof native_probe_patterns[0])
static int native_find_probes(const emu_t *host,const uint8_t *image,uint64_t *sites){
    unsigned matches[NATIVE_PROBE_PATTERNS]={0};
    memset(sites,0,NATIVE_PROBE_PATTERNS*sizeof *sites);
    for(int i=0;i<host->nsegs;i++){
        const seg_t *s=&host->segs[i];if(!(s->flags&1))continue;
        if(s->off>host->raw_len||s->filesz>host->raw_len-s->off)return -1;
        for(uint64_t j=0;j+sizeof native_probe_patterns[0]<=s->filesz;j+=4){
            for(unsigned p=0;p<NATIVE_PROBE_PATTERNS;p++){
                if(rd32(image,(size_t)(s->off+j))!=native_probe_patterns[p][0])continue;
                unsigned k=1;
                while(k<16&&rd32(image,(size_t)(s->off+j+k*4))==native_probe_patterns[p][k])k++;
                if(k==16){sites[p]=host->load_bias+s->va+j;matches[p]++;}
            }
        }
    }
    for(unsigned p=0;p<NATIVE_PROBE_PATTERNS;p++)if(matches[p]>1){
        fprintf(stderr,"error: ambiguous environment-probe signature %u\n",p);return -1;
    }
    return 0;
}
static int native_validate_probes(emu_t *host){
    uint8_t *image=malloc(host->raw_len);if(!image)return -1;
    memcpy(image,host->raw,host->raw_len);
    for(int i=0;i<host->nsegs;i++){
        const seg_t *s=&host->segs[i];if(!(s->flags&1))continue;
        if(s->off>host->raw_len||s->filesz>host->raw_len-s->off||
           uc_mem_read(host->uc,host->load_bias+s->va,image+s->off,s->filesz)){free(image);return -1;}
    }
    uint64_t sites[NATIVE_PROBE_PATTERNS]={0};int rc=native_find_probes(host,image,sites);free(image);
    return rc;
}
typedef struct {emu_t *host;uint64_t sites[NATIVE_PROBE_PATTERNS];unsigned count;} native_probe_state_t;
static void native_probe_observer(uc_engine *uc,uint64_t pc,uint32_t size,void *ud){
    native_probe_state_t *state=ud;uint32_t words[16];(void)size;
    if(uc_mem_read(uc,pc,words,4))return;
    if(words[0]!=native_probe_patterns[0][0]&&words[0]!=native_probe_patterns[1][0])return;
    if(!native_executable(state->host,pc)||!native_executable(state->host,pc+sizeof words-1)||
       uc_mem_read(uc,pc,words,sizeof words))return;
    for(unsigned p=0;p<NATIVE_PROBE_PATTERNS;p++){
        if(memcmp(words,native_probe_patterns[p],sizeof words))continue;
        if(!state->sites[p]){
            if(native_validate_probes(state->host)){state->host->stop=1;uc_emu_stop(uc);return;}
            state->sites[p]=pc;state->count++;
            fprintf(stderr,"[*] recognized offline environment probe at 0x%llx (signature %u)\n",
                    (unsigned long long)pc,p);
        }else if(state->sites[p]!=pc){
            fprintf(stderr,"error: environment-probe signature moved during execution\n");
            state->host->stop=1;uc_emu_stop(uc);return;
        }
        native_environment_probe(uc,pc,size,state->host);
        /* Stop before this translated block executes. run_unpack resumes at
         * the caller on the next chunk; no protected function is overwritten. */
        uc_emu_stop(uc);return;
    }
}
static void native_resolver_stop(uc_engine *uc,uint64_t pc,uint32_t size,void *ud){
    (void)pc;(void)size;*(uint64_t *)ud=rdreg(uc,R_X29);uc_emu_stop(uc);
}
static int native_constructor(emu_t *host,uint64_t entry){
    setup_regs(host->uc,entry,SENT_CTOR,0,STACK_TOP-0x1000,0);host->stop=0;
    for(unsigned i=0;i<1500&&!host->stop;i++){
        uint64_t pc=rdreg(host->uc,R_PC);uc_err rc=uc_emu_start(host->uc,pc,0,0,2000000);
        pc=rdreg(host->uc,R_PC);
        if(pc==SENT_CTOR&&(rc==UC_ERR_OK||rc==UC_ERR_FETCH_UNMAPPED))return 0;
        if(rc||!pc){fprintf(stderr,"error: game constructor stopped at 0x%llx: %s\n",
                            (unsigned long long)pc,uc_strerror(rc));return -1;}
    }
    fprintf(stderr,"error: game constructor did not complete\n");return -1;
}
static int64_t native_branch_delta(uint32_t word){
    int64_t value=word&0x3ffffffu;if(value&(1<<25))value-=1LL<<26;return value*4;
}
typedef struct {uint64_t resolver,stop;unsigned calls;} native_layout_t;
/* Dart AOT snapshots contain protected instruction blobs, not libg's BL
 * resolver. Recognize all four exported, file-backed snapshot ranges and
 * the two data headers; an arbitrary resolver-free ELF is not sufficient. */
static int native_dart_snapshot(const emu_t *game,const uint8_t *image){
    static const char *names[]={"_kDartVmSnapshotInstructions","_kDartIsolateSnapshotInstructions",
                                "_kDartVmSnapshotData","_kDartIsolateSnapshotData"};
    long table=va2file(game,game->symtab);if(!game->symtab||table<0)return 0;
    for(unsigned k=0;k<4;k++){
        unsigned found=0;
        for(int i=0;i<game->nsyms;i++)if(!strcmp(symname(game,i),names[k])){
            size_t p=(size_t)table+(size_t)i*24;
            if(p>game->raw_len||game->raw_len-p<24)return 0;
            uint64_t address=rd64(game->raw,p+8),length=rd64(game->raw,p+16);
            if(!length||address>UINT64_MAX-length)return 0;
            int backed=0;
            for(int j=0;j<game->nsegs;j++){
                const seg_t *s=&game->segs[j];
                if(address>=s->va&&address-s->va<s->filesz&&length<=s->filesz-(address-s->va)&&
                   !!(s->flags&1)==(k<2))backed=1;
            }
            long file=va2file(game,address);
            if(!backed||file<0||(size_t)file>game->raw_len||length>game->raw_len-(size_t)file)return 0;
            if(k>=2&&(length<24||rd32(image,(size_t)file)!=0xdcdcf5f5))return 0;
            found++;
        }
        if(found!=1)return 0;
    }
    return 1;
}
/* Discover the supported calling convention, not a build identity. A unique
 * save-frame entry and indirect tail branch are only candidates: every caller
 * is subsequently executed twice and checked by native_direct_calls(). */
static int native_discover(const emu_t *game,const uint8_t *image,native_layout_t *layout){
    native_layout_t found={0};unsigned entries=0,tails=0;
    for(int i=0;i<game->nsegs;i++){
        const seg_t *s=&game->segs[i];if(!(s->flags&1))continue;
        if(s->off>game->raw_len||s->filesz>game->raw_len-s->off)return -1;
        for(uint64_t j=0;j+4<=s->filesz;j+=4){
            size_t file=(size_t)(s->off+j);
            if(rd32(image,file)==0xd61f03a0){found.stop=s->va+j;tails++;}
            if(j+16<=s->filesz&&rd32(image,file)==0xa9bb7bfd&&
               rd32(image,file+4)==0x910003fd&&rd32(image,file+8)==0xa90107e0&&
               rd32(image,file+12)==0xa9020fe2){found.resolver=s->va+j;entries++;}
        }
    }
    if(!entries&&!tails&&native_dart_snapshot(game,image)){
        memset(layout,0,sizeof *layout);return 0;
    }
    if(entries!=1||tails!=1){
        fprintf(stderr,"error: ambiguous or unsupported resolver structure (%u entries, %u tails)\n",entries,tails);return -1;
    }
    for(int i=0;i<game->nsegs;i++){
        const seg_t *s=&game->segs[i];if(!(s->flags&1))continue;
        for(uint64_t j=0;j+4<=s->filesz;j+=4){
            uint32_t word=rd32(image,(size_t)(s->off+j));
            if((word&0xfc000000u)==0x94000000u&&
               (int64_t)(s->va+j)+native_branch_delta(word)==(int64_t)found.resolver)found.calls++;
        }
    }
    if(!found.calls){fprintf(stderr,"error: resolver has no direct callers\n");return -1;}
    *layout=found;return 0;
}
static int native_direct_calls(emu_t *host,emu_t *game,uint8_t *out,unsigned *count,
                               uint64_t resolver,uint64_t stop,unsigned expected){
    uint64_t destination=0;uc_hook hook;
    if(uc_hook_add(host->uc,&hook,UC_HOOK_CODE,native_resolver_stop,&destination,
                   game->load_bias+stop,game->load_bias+stop))return -1;
    int result=-1;unsigned found=0;
    for(int segment=0;segment<game->nsegs;segment++){
    const seg_t *s=&game->segs[segment];if(!(s->flags&1))continue;
    for(uint64_t local=0;local+4<=s->filesz;local+=4){
        uint64_t site=s->va+local,file=s->off+local;
        uint32_t word=rd32(out,(size_t)file);
        if((word&0xfc000000u)!=0x94000000u||(int64_t)site+native_branch_delta(word)!=(int64_t)resolver)continue;
        uint64_t targets[2]={0};found++;
        for(int trial=0;trial<2;trial++){
            destination=0;host->stop=0;
            uint64_t stack=STACK_TOP-0x1000;
            setup_regs(host->uc,game->load_bias+resolver,game->load_bias+site+4,
                       trial?0x1122334455667788ULL:0,stack,0);
            uint64_t registers[29]={0};
            for(int r=0;r<29;r++){
                registers[r]=trial?0x1122334455667788ULL+(uint64_t)r*0x1020304:0;
                wrreg(host->uc,UC_ARM64_REG_X0+r,registers[r]);
            }
            uc_err rc=uc_emu_start(host->uc,game->load_bias+resolver,0,0,1000000);
            uint32_t stub[2]={0};
            if(rc||host->stop||!destination||uc_mem_read(host->uc,destination,stub,sizeof stub)||
               !native_executable(game,destination)||!native_executable(game,destination+7)||
               stub[0]!=0xa8c57bfd||(stub[1]&0xfc000000u)!=0x14000000u){
                fprintf(stderr,"error: unrecognized call resolver at 0x%llx\n",(unsigned long long)site);goto done;
            }
            /* The two-instruction trampoline restores only FP/LR and 80 bytes
             * of stack. All argument and callee-saved registers must already
             * be intact before replacing the entire path with a direct BL. */
            uint64_t frame[2]={0};
            if(rdreg(host->uc,R_SP)!=stack-80||uc_mem_read(host->uc,stack-80,frame,sizeof frame)||
               frame[0]!=stack||frame[1]!=game->load_bias+site+4){
                fprintf(stderr,"error: resolver frame mismatch at 0x%llx\n",(unsigned long long)site);goto done;
            }
            for(int r=0;r<29;r++)if((r<8||r>=19)&&rdreg(host->uc,UC_ARM64_REG_X0+r)!=registers[r]){
                fprintf(stderr,"error: resolver changes x%d at 0x%llx\n",r,(unsigned long long)site);goto done;
            }
            targets[trial]=destination+4+native_branch_delta(stub[1]);
        }
        if(targets[0]!=targets[1]||!native_executable(game,targets[0])){
            fprintf(stderr,"error: unstable or external resolved target at 0x%llx\n",(unsigned long long)site);goto done;
        }
        int64_t delta=(int64_t)(targets[0]-game->load_bias)-(int64_t)site;
        if(delta%4||delta<-(1LL<<27)||delta>=(1LL<<27))goto done;
        uint32_t replacement=0x94000000u|((uint32_t)(delta/4)&0x3ffffffu);
        memcpy(out+file,&replacement,4);
    }
    }
    /* Independently discovered coverage must be complete. Never emit a partial patch. */
    if(found!=expected){fprintf(stderr,"error: expected %u verified resolver calls, found %u\n",expected,found);goto done;}
    *count=found;result=0;
done:
    uc_hook_del(host->uc,hook);return result;
}
static int native_restore_relocations(const emu_t *game,uint8_t *out){
    uint64_t tags[64]={0};if(dyn_tags(game,tags))return -1;
    uint64_t addresses[2]={tags[7],tags[23]},lengths[2]={tags[8],tags[2]};
    for(int table=0;table<2;table++){
        if(!lengths[table])continue;
        long file=va2file(game,addresses[table]);
        if(file<0||lengths[table]%24||(size_t)file>game->raw_len||lengths[table]>game->raw_len-(size_t)file)return -1;
        for(uint64_t i=0;i<lengths[table];i+=24){
            size_t p=(size_t)file+(size_t)i;uint64_t address=rd64(game->raw,p);
            uint32_t type=(uint32_t)rd64(game->raw,p+8);
            if(!type)continue;
            if(type!=1027&&type!=257&&type!=1025&&type!=1026&&type!=1031){
                fprintf(stderr,"error: unsupported export relocation type %u\n",type);return -1;
            }
            long target=va2file(game,address);if(target<0)continue; /* BSS is not serialized */
            /* R_AARCH64_TLSDESC is a resolver/argument pair, not one pointer. */
            size_t width=type==1031?16:8;
            if((size_t)target>game->raw_len||game->raw_len-(size_t)target<width)return -1;
            memcpy(out+(size_t)target,game->raw+(size_t)target,width);
        }
    }
    return 0;
}
static int native_write_new(const char *path,const void *data,size_t length){
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL,0644);if(fd<0)return -1;
    const uint8_t *p=data;size_t left=length;
    while(left){ssize_t n=write(fd,p,left);if(n<0&&errno==EINTR)continue;
        if(n<=0){close(fd);unlink(path);return -1;}p+=(size_t)n;left-=(size_t)n;}
    if(close(fd)){unlink(path);return -1;}return 0;
}
static void native_free_image(emu_t *image){
    for(int i=0;i<image->nsyms;i++)free(image->symnames[i]);
    free(image->symnames);free(image->raw);free(image->apk);apk_metadata_free(&image->package);
}
int ctxgen_native_unpack(const char *game_path,const char *shield_path,const char *apk_path,const char *outdir,int verbose){
    emu_t *host=calloc(1,sizeof *host),*game=calloc(1,sizeof *game);uint8_t *out=NULL,*reference=NULL;int result=-1;
    if(!host||!game){free(host);free(game);return -1;}g_verbose=verbose;
    struct stat st;
    if(!lstat(outdir,&st)||errno!=ENOENT){fprintf(stderr,"error: native output directory must not exist\n");goto done;}
    if(native_blob(game_path,&game->raw,&game->raw_len)||native_blob(shield_path,&host->raw,&host->raw_len)||
        native_blob(apk_path,&host->apk,&host->apk_len)){fprintf(stderr,"error: cannot read native inputs\n");goto done;}
    if(apk_read_metadata(host->apk,host->apk_len,&host->package)||elf_load(host)||elf_load(game))goto done;
    const char *shield_name=strrchr(shield_path,'/');
    host->image_name=shield_name?shield_name+1:shield_path;
    elf_syms(host);elf_syms(game);
    if(!host->nsyms||!game->nsyms)goto done;
    for(int i=0;i<host->nsegs;i++)if(host->segs[i].va>=0x1000000||host->segs[i].memsz>0x1000000-host->segs[i].va)goto done;
    for(int i=0;i<game->nsegs;i++)if(game->segs[i].va>=0x2000000||game->segs[i].memsz>0x2000000-game->segs[i].va)goto done;
    if(uc_open(UC_ARCH_ARM64,UC_MODE_LITTLE_ENDIAN,&host->uc)||emu_map(host)||apply_relocations(host))goto done;
    game->uc=host->uc;game->load_bias=0x1000000;game->imports=host;
    const char *base_name=strrchr(game_path,'/');
    game->image_name=base_name?base_name+1:game_path;host->peer=game;
    if(emu_map(game)||apply_relocations(game))goto done;
    uint64_t tls=TLS_BASE,canary=0x1122334455667788ULL;
    uc_reg_write(host->uc,UC_ARM64_REG_TPIDR_EL0,&tls);uc_mem_write(host->uc,TLS_BASE+0x28,&canary,8);
    host->heap_next=HEAP_BASE+0x1000;host->mmap_next=MMAP_BASE;host->errno_addr=MISC_BASE+0x1000;
    host->next_fd=0x200;host->file_next=MISC_BASE+0x4000;host->startup_budget=3000000000ULL;
    native_probe_state_t probes={0};probes.host=host;
    uc_hook observer;
    if(uc_hook_add(host->uc,&observer,UC_HOOK_BLOCK,native_probe_observer,&probes,1,0))goto done;
    if(run_unpack(host)||host->stop||rdreg(host->uc,R_PC)!=SENT_JNI||rdreg(host->uc,R_X0)!=0x10002){
        fprintf(stderr,"error: shield initialization did not complete (stop=%d, pc=0x%llx, JNI version=0x%llx)\n",
                host->stop,(unsigned long long)rdreg(host->uc,R_PC),(unsigned long long)rdreg(host->uc,R_X0));goto done;
    }
    if(native_constructor(host,game->load_bias+dyn_value(game,12)))goto done;
    fprintf(stderr,"[*] libg native loader returned; recovering protected call targets\n");
    out=malloc(game->raw_len);if(!out)goto done;memcpy(out,game->raw,game->raw_len);
    size_t changed=0;
    for(int i=0;i<game->nsegs;i++){
        const seg_t *s=&game->segs[i];if(!(s->flags&1))continue;
        if(s->off>game->raw_len||s->filesz>game->raw_len-s->off||uc_mem_read(host->uc,s->va+game->load_bias,out+s->off,s->filesz))goto done;
        for(uint64_t j=0;j<s->filesz;j++)changed+=out[s->off+j]!=game->raw[s->off+j];
    }
    unsigned calls=0;
    reference=malloc(game->raw_len);if(!reference)goto done;memcpy(reference,out,game->raw_len);
    native_layout_t layout;
    if(native_discover(game,out,&layout))goto done;
    fprintf(stderr,"[*] discovered resolver=0x%llx tail=0x%llx callers=%u\n",
            (unsigned long long)layout.resolver,(unsigned long long)layout.stop,layout.calls);
    if(!layout.calls&&!changed){fprintf(stderr,"error: Dart constructor decrypted no executable bytes\n");goto done;}
    if(layout.calls&&native_direct_calls(host,game,out,&calls,layout.resolver,layout.stop,layout.calls))goto done;
    if(native_restore_relocations(game,out))goto done;
    long init=va2file(game,dyn_value(game,12));if(init<0||(size_t)init>game->raw_len-4)goto done;
    uint32_t ret=0xd65f03c0;memcpy(out+(size_t)init,&ret,4);memset(out+24,0,8);
    char library[4096],report_path[4096],reference_path[4096],report[2048];
    if(snprintf(library,sizeof library,"%s/libg.unpacked.so",outdir)>=(int)sizeof library||
       snprintf(report_path,sizeof report_path,"%s/native-report.txt",outdir)>=(int)sizeof report_path||
       snprintf(reference_path,sizeof reference_path,"%s/libg.decrypted-reference.bin",outdir)>=(int)sizeof reference_path)goto done;
    int length=snprintf(report,sizeof report,
         "Automatic ARM64 native unpack\n"
         "APK version (metadata only): %s\n"
        "shield JNI_OnLoad: returned 0x10002\nlibg DT_INIT: returned\n"
        "changed executable bytes before call patches: %zu\nverified direct calls: %u\n"
         "resolver trials: two distinct register sets per site; arguments/callee-saved/frame verified\n"
         "export mode: %s\n"
        "export: original writable bytes and relocations; decrypted executable segments\n"
        "packed DT_INIT: replaced with RET; ELF entry point cleared\n"
         "instruction-matched offline environment-probe bypasses: %u\n"
         "libg.decrypted-reference.bin: analysis-only unpatched reference, NOT an installable library\n"
        "requires patched Java, matching native dependencies and full install-time assets\n"
         "runtime/device/server validation: not performed by this export command\n",host->package.version,changed,calls,
          layout.calls?"verified direct-call resolver":"Dart AOT snapshot (no resolver sites)",probes.count);
    if(length<0||length>=(int)sizeof report||mkdir(outdir,0755))goto done;
    if(native_write_new(library,out,game->raw_len)||native_write_new(report_path,report,(size_t)length)||
       native_write_new(reference_path,reference,game->raw_len)){
        fprintf(stderr,"error: cannot write native artifacts\n");goto done;
    }
    fprintf(stderr,"[+] wrote %s (%u verified direct-call patches); full APK assets/dependencies required; export is not runtime validation\n",library,calls);result=0;
done:
    game->uc=NULL;emu_free(host);native_free_image(game);native_free_image(host);free(reference);free(out);free(game);free(host);return result;
}
/* Resolve the shield's real sparse string IDs. The caller must additionally
 * authenticate these values against LBTS plaintext before emitting Java. */
static int native_jni_call(emu_t *e,uint64_t function,uint64_t a2,uint64_t a3){
    e->stop=0;setup_regs(e->uc,function,SENT_CTOR,JNI_ENV,STACK_TOP-0x1000,0);
    wrreg(e->uc,R_X2,a2);wrreg(e->uc,UC_ARM64_REG_X3,a3);
    for(unsigned i=0;i<50;i++){
        uc_err rc=uc_emu_start(e->uc,rdreg(e->uc,R_PC),0,0,2000000);
        if(!e->stop&&rdreg(e->uc,R_PC)==SENT_CTOR&&(rc==UC_ERR_OK||rc==UC_ERR_FETCH_UNMAPPED))return 0;
        if(e->stop||rc)return -1;
    }
    return -1;
}
int ctxgen_strings(const char *shield,const char *apk,const char *owner,uint32_t registration,const char *ids,const char *output){
    emu_t *e=calloc(1,sizeof *e);FILE *in=NULL,*out=NULL;int result=-1;char *value=NULL;
    if(!e)return -1;
    struct stat st;if(!lstat(output,&st)||errno!=ENOENT)goto done;
    if(native_blob(shield,&e->raw,&e->raw_len)||native_blob(apk,&e->apk,&e->apk_len)||
       apk_read_metadata(e->apk,e->apk_len,&e->package)||elf_load(e))goto done;
    const char *base=strrchr(shield,'/');e->image_name=base?base+1:shield;
    elf_syms(e);
    if(uc_open(UC_ARCH_ARM64,UC_MODE_LITTLE_ENDIAN,&e->uc)||emu_map(e)||apply_relocations(e))goto done;
    uint64_t tls=TLS_BASE,canary=0x1122334455667788ULL;
    uc_reg_write(e->uc,UC_ARM64_REG_TPIDR_EL0,&tls);uc_mem_write(e->uc,TLS_BASE+0x28,&canary,8);
    e->heap_next=HEAP_BASE+0x1000;e->mmap_next=MMAP_BASE;e->errno_addr=MISC_BASE+0x1000;
    e->next_fd=0x200;e->file_next=MISC_BASE+0x4000;e->startup_budget=3000000000ULL;
    if(run_unpack(e)||e->stop||rdreg(e->uc,R_PC)!=SENT_JNI||rdreg(e->uc,R_X0)!=0x10002)goto done;
    uint64_t registrar=0;unsigned matches=0;
    for(unsigned i=0;i<e->nnatives;i++)if(!strcmp(e->natives[i].signature,"(Ljava/lang/Class;I)V")){
        registrar=e->natives[i].function;matches++;
    }
    if(matches!=1)goto done;
    uint64_t clazz=heap_alloc(e,strlen(owner)+1,0);write_cstr(e,clazz,owner);
    if(native_jni_call(e,registrar,clazz,registration))goto done;
    uint64_t function=0;matches=0;
    for(unsigned i=0;i<e->nnatives;i++)if(!strcmp(e->natives[i].owner,owner)&&
        !strcmp(e->natives[i].signature,"(I)Ljava/lang/String;")){function=e->natives[i].function;matches++;}
    if(matches!=1)goto done;
    in=fopen(ids,"r");if(!in)goto done;
    int fd=open(output,O_WRONLY|O_CREAT|O_EXCL,0644);if(fd<0)goto done;
    out=fdopen(fd,"w");if(!out){close(fd);unlink(output);goto done;}
    value=malloc(65536);if(!value)goto done;
    unsigned id,count=0;
    while(fscanf(in,"%x",&id)==1){
        if(++count>65536||native_jni_call(e,function,id,0)||!rdreg(e->uc,R_X0))goto done;
        size_t length=read_cstr(e,rdreg(e->uc,R_X0),value,65536);
        if(length>=65535)goto done;
        fprintf(out,"%08x\t",id);
        for(size_t j=0;j<length;j++)fprintf(out,"%02x",(unsigned char)value[j]);
        fputc('\n',out);
    }
    if(!feof(in)||!count||ferror(in)||ferror(out))goto done;
    fprintf(stderr,"[+] resolved %u sparse string IDs through the original shield\n",count);result=0;
done:
    if(in)fclose(in);
    if(out){if(fclose(out))result=-1;if(result)unlink(output);}
    if(result)fprintf(stderr,"error: native sparse string recovery failed\n");
    emu_free(e);native_free_image(e);free(value);free(e);return result;
}
#endif
