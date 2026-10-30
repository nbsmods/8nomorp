/* Internal emulator regression checks; no game assets or device required. */
#include "../src/ctxgen.c"
#include <assert.h>

static int64_t syscall_result(emu_t *e, uint64_t nr, uint64_t a0, uint64_t a1){
    wrreg(e->uc, UC_ARM64_REG_X8, nr);
    wrreg(e->uc, R_X0, a0); wrreg(e->uc, R_X1, a1);
    wrreg(e->uc, R_X2, 0); wrreg(e->uc, UC_ARM64_REG_X3, 0);
    hook_intr(e->uc, 2, e);
    return (int64_t)rdreg(e->uc, R_X0);
}
static void put64(uint8_t *p,size_t off,uint64_t v){memcpy(p+off,&v,8);}
static void put32(uint8_t *p,size_t off,uint32_t v){memcpy(p+off,&v,4);}
static void test_native_segment_targets(void){
    emu_t *game=calloc(1,sizeof *game);assert(game);
    game->load_bias=0x1000000;game->nsegs=3;
    game->segs[0]=(seg_t){0};game->segs[0].va=0;game->segs[0].filesz=0x1000;game->segs[0].flags=5;
    game->segs[1]=(seg_t){0};game->segs[1].va=0x2000;game->segs[1].filesz=0x1000;game->segs[1].flags=6;
    game->segs[2]=(seg_t){0};game->segs[2].va=0x1310000;game->segs[2].filesz=0x10000;game->segs[2].flags=5;
    assert(native_executable(game,game->load_bias+0x100));
    /* Regression: these are executable code islands, not external shield code. */
    assert(native_executable(game,game->load_bias+0x13143e8));
    assert(native_executable(game,game->load_bias+0x1313780));
    assert(!native_executable(game,game->load_bias+0x1310000+0x10000));
    assert(!native_executable(game,game->load_bias+0x2000));
    assert(!native_executable(game,game->load_bias-4));
    assert(native_branch_delta(0x17ffffff)==-4);
    assert(native_branch_delta(0x14000001)==4);
    free(game);
}
static void test_native_direct_resolver(void){
    emu_t *host=calloc(1,sizeof *host),*game=calloc(1,sizeof *game);assert(host&&game);
    assert(!uc_open(UC_ARCH_ARM64,UC_MODE_LITTLE_ENDIAN,&host->uc));
    assert(!uc_mem_map(host->uc,0x1000,0x1000,UC_PROT_ALL));
    assert(!uc_mem_map(host->uc,STACK_TOP-0x10000,0x10000,UC_PROT_ALL));
    game->nsegs=1;game->segs[0]=(seg_t){0};
    game->segs[0].va=0x1000;game->segs[0].filesz=0x1000;game->segs[0].flags=5;
    uint8_t out[0x1000]={0};
    /* Save the real resolver's 80-byte frame; select a file-backed trampoline
     * without changing argument or callee-saved registers. */
    put32(out,0,0xa9bb7bfd);put32(out,4,0x910003fd);
    put32(out,8,0x100007dd); /* adr x29, 0x1100 */
    put32(out,12,0xd61f03a0); /* br x29: stop before the final trampoline */
    put32(out,0x80,0x97ffffe0); /* bl 0x1000 */
    put32(out,0x100,0xa8c57bfd);put32(out,0x104,0x1400003f); /* -> 0x1200 */
    assert(!uc_mem_write(host->uc,0x1000,out,sizeof out));
    unsigned count=0;
    assert(!native_direct_calls(host,game,out,&count,0x1000,0x100c,1));
    assert(count==1 && rd32(out,0x80)==0x94000060); /* bl 0x1200 */
    /* A changed native calling convention must not be silently accepted. */
    put32(out,0x80,0x97ffffe0);
    uint32_t corrupt=0xd2800020; /* mov x0,#1 instead of mov fp,sp */
    assert(!uc_mem_write(host->uc,0x1004,&corrupt,4));
    assert(!uc_ctl_remove_cache(host->uc,0x1000,0x1100));
    assert(native_direct_calls(host,game,out,&count,0x1000,0x100c,1)<0);
    uc_close(host->uc);free(host);free(game);
}
static void test_native_discovery(void){
    emu_t game={0};uint8_t image[0x400]={0};game.raw_len=sizeof image;
    game.nsegs=2;game.segs[0]=(seg_t){0};game.segs[1]=(seg_t){0};
    game.segs[0].off=0x40;game.segs[0].filesz=0x200;game.segs[0].flags=5;
    game.segs[1].off=0x280;game.segs[1].filesz=0x100;game.segs[1].flags=6;
    for(unsigned shift=0;shift<17;shift++){
        uint64_t base=0x2000+shift*0x10000;game.segs[0].va=base;
        memset(image,0,sizeof image);
        for(int copy=0;copy<2;copy++){
            size_t p=copy?0x280:0x40;
            put32(image,p,0xa9bb7bfd);put32(image,p+4,0x910003fd);
            put32(image,p+8,0xa90107e0);put32(image,p+12,0xa9020fe2);
            put32(image,p+0x3c,0xd61f03a0);
        }
        put32(image,0xc0,0x97ffffe0); /* call backwards by 0x80 */
        native_layout_t found={0};
        assert(!native_discover(&game,image,&found));
        assert(found.resolver==base&&found.stop==base+0x3c&&found.calls==1);
        put32(image,0xc4,0x97ffffdf);
        assert(!native_discover(&game,image,&found)&&found.calls==2);
        put32(image,0x80,0xd61f03a0); /* ambiguous executable tail */
        assert(native_discover(&game,image,&found)<0);
        put32(image,0x80,0);put32(image,0xc0,0);put32(image,0xc4,0);
        assert(native_discover(&game,image,&found)<0);
    }
    game.segs[0].filesz=sizeof image; /* out-of-file executable bytes */
    native_layout_t found={0};assert(native_discover(&game,image,&found)<0);
}
static void test_native_tls_export(void){
    emu_t game={0};uint8_t raw[0x400]={0},out[0x400];memset(out,0xff,sizeof out);
    game.raw=raw;game.raw_len=sizeof raw;game.nsegs=1;
    game.segs[0].va=0x1000;game.segs[0].filesz=sizeof raw;
    put64(raw,0x20,0x40);raw[56]=1;
    put32(raw,0x40,2);put64(raw,0x50,0x1100);put64(raw,0x60,48);
    put64(raw,0x100,7);put64(raw,0x108,0x1180);
    put64(raw,0x110,8);put64(raw,0x118,24);
    put64(raw,0x180,0x1200);put64(raw,0x188,1031);
    for(unsigned i=0;i<16;i++)raw[0x200+i]=(uint8_t)i;
    assert(!native_restore_relocations(&game,out));
    assert(!memcmp(raw+0x200,out+0x200,16));assert(out[0x210]==0xff);
    put64(raw,0x180,0x13f8);assert(native_restore_relocations(&game,out)<0);
    put64(raw,0x188,9999);assert(native_restore_relocations(&game,out)<0);
}
static void test_dart_snapshot_discovery(void){
    emu_t game={0};uint8_t image[0x400]={0};
    char *names[]={"","_kDartVmSnapshotInstructions","_kDartIsolateSnapshotInstructions",
                   "_kDartVmSnapshotData","_kDartIsolateSnapshotData"};
    game.raw=image;game.raw_len=sizeof image;game.symnames=names;game.nsyms=5;game.symtab=0x1020;
    game.nsegs=2;
    game.segs[0].va=0x1000;game.segs[0].filesz=0x200;game.segs[0].flags=4;
    game.segs[1].va=0x2000;game.segs[1].off=0x200;game.segs[1].filesz=0x200;game.segs[1].flags=5;
    for(unsigned i=1;i<5;i++){
        put64(image,0x20+i*24+8,i<3?0x2000+(i-1)*0x40:0x10a0+(i-3)*0x20);
        put64(image,0x20+i*24+16,0x20);
    }
    put32(image,0xa0,0xdcdcf5f5);put32(image,0xc0,0xdcdcf5f5);
    assert(native_dart_snapshot(&game,image));
    native_layout_t layout={0};assert(!native_discover(&game,image,&layout));assert(!layout.calls);
    put32(image,0xc0,0);assert(!native_dart_snapshot(&game,image));assert(native_discover(&game,image,&layout)<0);
    put32(image,0xc0,0xdcdcf5f5);
    put32(image,0x200,0xd61f03a0);assert(native_discover(&game,image,&layout)<0);
    put32(image,0x200,0);put64(image,0x20+24+16,0x1000);assert(!native_dart_snapshot(&game,image));
}
static void test_native_probe_discovery(void){
    emu_t host={0};uint8_t image[0x400]={0};host.raw_len=sizeof image;
    host.nsegs=2;host.segs[0]=(seg_t){0};host.segs[1]=(seg_t){0};
    host.segs[0].off=0x40;host.segs[0].filesz=0x200;host.segs[0].flags=5;
    host.segs[1].off=0x280;host.segs[1].filesz=0x100;host.segs[1].flags=6;
    for(unsigned p=0;p<NATIVE_PROBE_PATTERNS;p++){
        for(unsigned shift=0;shift<5;shift++){
            memset(image,0,sizeof image);host.load_bias=shift*0x10000;
            host.segs[0].va=0x2000+shift*0x1000;
            for(unsigned k=0;k<16;k++){
                put32(image,0x80+k*4,native_probe_patterns[p][k]);
                put32(image,0x280+k*4,native_probe_patterns[p][k]); /* non-executable decoy */
            }
            uint64_t sites[NATIVE_PROBE_PATTERNS];
            assert(!native_find_probes(&host,image,sites));
            for(unsigned q=0;q<NATIVE_PROBE_PATTERNS;q++)
                assert(sites[q]==(p==q?host.load_bias+host.segs[0].va+0x40:0));
            for(unsigned k=0;k<16;k++)put32(image,0x100+k*4,native_probe_patterns[p][k]);
            assert(native_find_probes(&host,image,sites)<0);
            memset(image+0x100,0,64);image[0x84]^=1; /* incomplete signature must not bypass */
            assert(!native_find_probes(&host,image,sites));
            for(unsigned q=0;q<NATIVE_PROBE_PATTERNS;q++)assert(!sites[q]);
        }
    }
}
static void test_native_probe_observer(void){
    emu_t *host=calloc(1,sizeof *host);assert(host);
    host->raw_len=0x1000;host->raw=calloc(1,host->raw_len);assert(host->raw);
    host->nsegs=1;host->segs[0]=(seg_t){0};host->segs[0].va=0x1000;
    host->segs[0].filesz=0x1000;host->segs[0].flags=5;
    assert(!uc_open(UC_ARCH_ARM64,UC_MODE_LITTLE_ENDIAN,&host->uc));
    assert(!uc_mem_map(host->uc,0x1000,0x1000,UC_PROT_ALL));
    assert(!uc_mem_write(host->uc,0x1000,native_probe_patterns[0],64));
    native_probe_state_t state={0};state.host=host;uc_hook observer;
    assert(!uc_hook_add(host->uc,&observer,UC_HOOK_BLOCK,native_probe_observer,&state,1,0));
    setup_regs(host->uc,0x1000,0x1800,99,STACK_TOP-0x1000,0);
    assert(!uc_emu_start(host->uc,0x1000,0,0,100));
    assert(state.count==1&&state.sites[0]==0x1000&&!host->stop);
    assert(rdreg(host->uc,R_PC)==0x1800&&rdreg(host->uc,R_X0)==0);
    assert(rdreg(host->uc,R_SP)==STACK_TOP-0x1000); /* prologue did not execute */
    assert(!uc_mem_write(host->uc,0x1200,native_probe_patterns[0],64));
    memset(&state,0,sizeof state);state.host=host;
    setup_regs(host->uc,0x1000,0x1800,99,STACK_TOP-0x1000,0);
    assert(!uc_emu_start(host->uc,0x1000,0,0,100));
    assert(host->stop&&state.count==0); /* ambiguity stops, never bypasses */
    uc_close(host->uc);free(host->raw);free(host);
}
static void test_gnu_symbols(void){
    emu_t *e=calloc(1,sizeof *e);assert(e);
    e->raw_len=4096;e->raw=calloc(1,e->raw_len);assert(e->raw);
    memcpy(e->raw,"\177ELF",4);e->raw[4]=2;
    put64(e->raw,32,64);put32(e->raw,54,56|(2u<<16));
    put32(e->raw,64,1);put64(e->raw,64+32,4096);put64(e->raw,64+40,4096);
    put32(e->raw,120,2);put64(e->raw,128,0x100);put64(e->raw,136,0x100);put64(e->raw,152,80);
    put64(e->raw,0x100,6);put64(e->raw,0x108,0x200);
    put64(e->raw,0x110,5);put64(e->raw,0x118,0x300);
    put64(e->raw,0x120,0x6ffffef5);put64(e->raw,0x128,0x380);
    put32(e->raw,0x218,1);put32(e->raw,0x230,5);
    e->raw[0x230+6]=1;put64(e->raw,0x230+8,0x400);
    memcpy(e->raw+0x300,"\0foo\0bar\0",9);
    put32(e->raw,0x380,1);put32(e->raw,0x384,2);put32(e->raw,0x388,1);
    put32(e->raw,0x398,2);put32(e->raw,0x39c,1);
    assert(!elf_load(e));elf_syms(e);assert(e->nsyms==3);
    assert(!strcmp(symname(e,1),"foo") && !strcmp(symname(e,2),"bar"));
    e->load_bias=0x1000000;
    assert(relocated_symbol(e,2)==e->load_bias+0x400);
    emu_t *host=calloc(1,sizeof *host);assert(host);e->imports=host;
    assert(relocated_symbol(e,1)==stub_for(host,"foo"));
    for(int i=0;i<e->nsyms;i++)free(e->symnames[i]);
    free(e->symnames);free(e->raw);free(e);free(host);
}
static void test_dl_info(void){
    emu_t *e=calloc(1,sizeof *e),*peer=calloc(1,sizeof *peer);assert(e&&peer);
    assert(!uc_open(UC_ARCH_ARM64,UC_MODE_LITTLE_ENDIAN,&e->uc));
    assert(!uc_mem_map(e->uc,HEAP_BASE,0x10000,UC_PROT_ALL));e->heap_next=HEAP_BASE;
    e->raw_len=4096;e->raw=calloc(1,e->raw_len);assert(e->raw);
    put64(e->raw,32,64);put32(e->raw,54,56|(1u<<16));
    e->nsegs=1;e->segs[0]=(seg_t){0};e->segs[0].va=0x10000;e->segs[0].filesz=4096;e->segs[0].memsz=4096;
    *peer=*e;peer->load_bias=0x20000;peer->image_name="libg.so";e->peer=peer;
    wrreg(e->uc,R_X0,0x123456);wrreg(e->uc,R_X1,0x456);wrreg(e->uc,R_X30,0x789);
    dispatch_import(e,"dl_iterate_phdr");
    uint64_t info[8]={0};uc_mem_read(e->uc,rdreg(e->uc,R_X0),info,sizeof info);
    assert(info[0]==0 && info[2]==0x10040 && info[3]==1);
    assert(rdreg(e->uc,R_PC)==0x123456 && rdreg(e->uc,R_X2)==0x456 && e->phdr_depth[0]==1);
    wrreg(e->uc,R_X0,0);dispatch_import(e,"emu_phdr_resume");
    uc_mem_read(e->uc,rdreg(e->uc,R_X0),info,sizeof info);
    assert(info[0]==0x20000 && info[2]==0x30040);
    wrreg(e->uc,R_X0,0);dispatch_import(e,"emu_phdr_resume");
    assert(rdreg(e->uc,R_PC)==0x789 && !rdreg(e->uc,R_X0) && !e->phdr_depth[0]);
    wrreg(e->uc,R_X0,0x123456);wrreg(e->uc,R_X1,0);wrreg(e->uc,R_X30,0x789);
    dispatch_import(e,"dl_iterate_phdr");
    wrreg(e->uc,R_X0,7);dispatch_import(e,"emu_phdr_resume");
    assert(rdreg(e->uc,R_PC)==0x789 && rdreg(e->uc,R_X0)==7 && !e->phdr_depth[0]);
    wrreg(e->uc,R_X0,0x30080);wrreg(e->uc,R_X1,HEAP_BASE+0x8000);dispatch_import(e,"dladdr");
    assert(rdreg(e->uc,R_X0)==1);uc_mem_read(e->uc,HEAP_BASE+0x8000,info,32);assert(info[1]==0x20000);
    uc_close(e->uc);free(e->raw);free(peer);free(e);
}
static void test_inflate_bridge(void){
    emu_t *e=calloc(1,sizeof *e);assert(e);
    assert(!uc_open(UC_ARCH_ARM64,UC_MODE_LITTLE_ENDIAN,&e->uc));
    assert(!uc_mem_map(e->uc,HEAP_BASE,0x10000,UC_PROT_ALL));
    uint8_t payload[1024],packed[2048],stream[112]={0},decoded[1024];
    for(size_t i=0;i<sizeof payload;i++)payload[i]=(uint8_t)(i%37);
    uLongf len=sizeof packed;assert(compress2(packed,&len,payload,sizeof payload,Z_BEST_COMPRESSION)==Z_OK);
    uc_mem_write(e->uc,HEAP_BASE+0x1000,packed,len);uc_mem_write(e->uc,HEAP_BASE+0x500,ZLIB_VERSION,sizeof ZLIB_VERSION);
    put64(stream,0,HEAP_BASE+0x1000);put32(stream,8,(uint32_t)len);
    put64(stream,24,HEAP_BASE+0x2000);put32(stream,32,128);
    uc_mem_write(e->uc,HEAP_BASE,stream,sizeof stream);
    wrreg(e->uc,R_X0,HEAP_BASE);wrreg(e->uc,R_X1,MAX_WBITS);wrreg(e->uc,R_X2,HEAP_BASE+0x500);wrreg(e->uc,UC_ARM64_REG_X3,112);
    dispatch_import(e,"inflateInit2_");assert((int64_t)rdreg(e->uc,R_X0)==Z_OK);
    wrreg(e->uc,R_X0,HEAP_BASE);wrreg(e->uc,R_X1,Z_NO_FLUSH);dispatch_import(e,"inflate");
    assert((int64_t)rdreg(e->uc,R_X0)==Z_OK);
    uc_mem_read(e->uc,HEAP_BASE,stream,sizeof stream);assert(rd64(stream,40)==128);
    put32(stream,32,sizeof payload-128);uc_mem_write(e->uc,HEAP_BASE,stream,sizeof stream);
    wrreg(e->uc,R_X0,HEAP_BASE);wrreg(e->uc,R_X1,Z_FINISH);dispatch_import(e,"inflate");
    assert((int64_t)rdreg(e->uc,R_X0)==Z_STREAM_END);
    uc_mem_read(e->uc,HEAP_BASE+0x2000,decoded,sizeof decoded);assert(!memcmp(payload,decoded,sizeof payload));
    uc_mem_read(e->uc,HEAP_BASE,stream,sizeof stream);assert(rd64(stream,40)==sizeof payload && !rd32(stream,8));
    wrreg(e->uc,R_X0,HEAP_BASE);dispatch_import(e,"inflateEnd");assert((int64_t)rdreg(e->uc,R_X0)==Z_OK);
    wrreg(e->uc,R_X0,HEAP_BASE);dispatch_import(e,"inflateEnd");assert((int64_t)rdreg(e->uc,R_X0)==Z_STREAM_ERROR);
    emu_free(e);free(e);
}
int main(void){
    test_native_segment_targets();
    test_native_direct_resolver();
    test_native_discovery();
    test_dart_snapshot_discovery();
    test_native_tls_export();
    test_native_probe_discovery();
    test_native_probe_observer();
    test_gnu_symbols();
    test_dl_info();
    test_inflate_bridge();
    emu_t e = {0};
    assert(!uc_open(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, &e.uc));
    wrreg(e.uc,R_X0,39);                          /* Android _SC_PAGESIZE */
    dispatch_import(&e,"sysconf");
    assert(rdreg(e.uc,R_X0)==4096);
    assert(syscall_result(&e,172,0,0)==1234);
    assert(syscall_result(&e,173,0,0)==500);
    e.cur_ctx=1; e.th[0].pid=4096; e.th[0].ppid=1234;
    assert(syscall_result(&e,172,0,0)==4096);
    assert(syscall_result(&e,173,0,0)==1234);
    assert(syscall_result(&e,117,16,(uint32_t)-1)==-3);
    assert(syscall_result(&e,117,16,1234)==0);
    assert(e.trace_pending && e.trace_stopped);
    assert(syscall_result(&e,117,0x4200,1234)==0);
    assert(syscall_result(&e,117,7,1234)==0 && !e.trace_stopped);
    assert(syscall_result(&e,117,17,1234)==0 && !e.trace_pid);
    assert(!uc_mem_map(e.uc,HEAP_BASE,0x1000,UC_PROT_ALL));
    assert(!uc_mem_map(e.uc,STACK_TOP-STACK_SIZE,STACK_SIZE,UC_PROT_ALL));
    assert(!uc_mem_map(e.uc,TLS_BASE,TLS_SIZE,UC_PROT_ALL));
    assert(!uc_mem_map(e.uc,0x10000,0x1000,UC_PROT_ALL));
    wrreg(e.uc,R_X0,123);wrreg(e.uc,R_X1,123);dispatch_import(&e,"pthread_equal");
    assert(rdreg(e.uc,R_X0)==1);
    wrreg(e.uc,R_X0,123);wrreg(e.uc,R_X1,124);dispatch_import(&e,"pthread_equal");
    assert(rdreg(e.uc,R_X0)==0);
    wrreg(e.uc,R_X0,HEAP_BASE);dispatch_import(&e,"pthread_key_create");
    assert(rdreg(e.uc,R_X0)==0 && e.next_key==1);
    uint32_t key=99;uc_mem_read(e.uc,HEAP_BASE,&key,4);assert(key==0);
    e.cur_ctx=0;wrreg(e.uc,R_X0,key);wrreg(e.uc,R_X1,0xabcdef);
    dispatch_import(&e,"pthread_setspecific");assert(rdreg(e.uc,R_X0)==0);
    e.cur_ctx=1;wrreg(e.uc,R_X0,key);dispatch_import(&e,"pthread_getspecific");assert(!rdreg(e.uc,R_X0));
    e.cur_ctx=0;wrreg(e.uc,R_X0,key);dispatch_import(&e,"pthread_getspecific");assert(rdreg(e.uc,R_X0)==0xabcdef);
    wrreg(e.uc,R_X0,1);wrreg(e.uc,R_X1,HEAP_BASE);dispatch_import(&e,"jvm_AttachCurrentThread");
    assert(!rdreg(e.uc,R_X0));uint64_t env=0;uc_mem_read(e.uc,HEAP_BASE,&env,8);assert(env==JNI_ENV);
    assert(!guest_clock(&e,HEAP_BASE,0,0));
    uint64_t stamp[2]={0},later[2]={0};uc_mem_read(e.uc,HEAP_BASE,stamp,sizeof stamp);
    assert(!guest_clock(&e,HEAP_BASE,0,0));uc_mem_read(e.uc,HEAP_BASE,later,sizeof later);
    assert(later[0]*1000000000+later[1]>stamp[0]*1000000000+stamp[1]);
    e.heap_next=HEAP_BASE+0x800;
    write_cstr(&e,HEAP_BASE+0x100,"example/Owner");write_cstr(&e,HEAP_BASE+0x200,"pipeFd");write_cstr(&e,HEAP_BASE+0x300,"I");
    wrreg(e.uc,R_X1,HEAP_BASE+0x100);wrreg(e.uc,R_X2,HEAP_BASE+0x200);wrreg(e.uc,UC_ARM64_REG_X3,HEAP_BASE+0x300);
    dispatch_import(&e,"jni_144");uint64_t field=rdreg(e.uc,R_X0);assert(field && e.nstatic_fields==1);
    dispatch_import(&e,"jni_144");assert(rdreg(e.uc,R_X0)==field && e.nstatic_fields==1);
    wrreg(e.uc,R_X2,field);wrreg(e.uc,UC_ARM64_REG_X3,521);dispatch_import(&e,"jni_159");assert(!rdreg(e.uc,R_X0));
    wrreg(e.uc,R_X2,field);dispatch_import(&e,"jni_150");assert(rdreg(e.uc,R_X0)==521);
    write_cstr(&e,HEAP_BASE+0x420,"nativeEntry");write_cstr(&e,HEAP_BASE+0x440,"()V");
    uint64_t registration[3]={HEAP_BASE+0x420,HEAP_BASE+0x440,0x10000};
    uc_mem_write(e.uc,HEAP_BASE+0x400,registration,sizeof registration);
    wrreg(e.uc,R_X1,HEAP_BASE+0x100);wrreg(e.uc,R_X2,HEAP_BASE+0x400);wrreg(e.uc,UC_ARM64_REG_X3,1);
    dispatch_import(&e,"jni_215");assert(!rdreg(e.uc,R_X0) && e.nnatives==1);
    assert(!strcmp(e.natives[0].owner,"example/Owner") && !strcmp(e.natives[0].name,"nativeEntry") && e.natives[0].function==0x10000);
    e.errno_addr=HEAP_BASE+0x900;write_cstr(&e,HEAP_BASE+0x500,"/system/xbin/su");
    wrreg(e.uc,R_X0,HEAP_BASE+0x500);wrreg(e.uc,R_X1,0);dispatch_import(&e,"access");
    assert((int64_t)rdreg(e.uc,R_X0)==-1);uint32_t file_error=0;uc_mem_read(e.uc,e.errno_addr,&file_error,4);assert(file_error==2);
    snprintf(e.natives[1].owner,sizeof e.natives[1].owner,"elsm/a");
    snprintf(e.natives[1].name,sizeof e.natives[1].name,"b");
    snprintf(e.natives[1].signature,sizeof e.natives[1].signature,"()V");e.natives[1].function=0x123456;e.nnatives=2;
    write_cstr(&e,HEAP_BASE+0x100,"elsm/a");wrreg(e.uc,R_X0,JNI_ENV);wrreg(e.uc,R_X1,HEAP_BASE+0x100);wrreg(e.uc,R_X30,0x789);
    dispatch_import(&e,"jni_29");assert(rdreg(e.uc,R_PC)==0x123456 && e.constructor_depth[0]==1);
    uint64_t instance=rdreg(e.uc,R_X1);write_cstr(&e,HEAP_BASE+0x200,"a");
    wrreg(e.uc,R_X1,instance);wrreg(e.uc,R_X2,HEAP_BASE+0x200);wrreg(e.uc,UC_ARM64_REG_X3,0x1122334455667788ULL);
    dispatch_import(&e,"jni_110");assert(!rdreg(e.uc,R_X0));
    wrreg(e.uc,R_X1,instance);wrreg(e.uc,R_X2,HEAP_BASE+0x200);dispatch_import(&e,"jni_101");assert(rdreg(e.uc,R_X0)==0x1122334455667788ULL);
    dispatch_import(&e,"emu_constructor_resume");assert(rdreg(e.uc,R_X0)==instance && rdreg(e.uc,R_PC)==0x789 && !e.constructor_depth[0]);
    fakefile_t *ff=&e.files[e.nfiles++];
    ff->kind=2;ff->fd=200;ff->content=strdup("apk fixture");ff->len=11;
    assert(file_seek(ff,-3,2)==8 && file_seek(ff,-9,1)==-22);
    assert(file_seek(ff,0,2)==11 && file_seek(ff,2,0)==2);
    assert(!guest_fstat(&e,200,HEAP_BASE));
    uint64_t file_size=0;uc_mem_read(e.uc,HEAP_BASE+48,&file_size,8);assert(file_size==11);
    e.mmap_next=MMAP_BASE;
    int64_t mapping=guest_mmap(&e,4096,2,200,4);assert(mapping==(int64_t)MMAP_BASE);
    char mapped[8]={0};uc_mem_read(e.uc,(uint64_t)mapping,mapped,7);assert(!strcmp(mapped,"fixture"));
    e.nsegs=1; e.segs[0].va=0x10000; e.segs[0].memsz=0x1000; e.segs[0].flags=2;
    e.heap_next=HEAP_BASE+0x1000;
    uint64_t original=0x12345678, zero=0, actual=0;
    uc_mem_write(e.uc,0x10000,&original,8);
    uc_mem_write(e.uc,HEAP_BASE,&original,8);
    int count=0; region_t *saved=fork_mem_save(&e,&count);
    assert(saved && count==4);
    uc_mem_write(e.uc,0x10000,&zero,8); uc_mem_write(e.uc,HEAP_BASE,&zero,8);
    fork_mem_restore(&e,saved,count);
    uc_mem_read(e.uc,0x10000,&actual,8); assert(actual==original);
    uc_mem_read(e.uc,HEAP_BASE,&actual,8); assert(actual==original);
    fork_mem_free(saved,count);
    /* mov x0,#42; eor v0.16b,v0.16b,v0.16b; cmp x0,x0; ret */
    const uint32_t code[]={0xd2800540,0x6e201c00,0xeb00001f,0xd65f03c0};
    uc_mem_write(e.uc,0x10000,code,sizeof code);
    e.cur_ctx=0; e.nth=1; e.th[0].state=1;
    e.th[0].pc=0x10000; e.th[0].sp=STACK_TOP-0x1000; e.th[0].regs[30]=SENT_THREAD;
    uint64_t flags=0xa0000000;
    uint8_t vector[16],restored[16]; memset(vector,0xab,sizeof vector);
    uc_reg_write(e.uc,UC_ARM64_REG_NZCV,&flags);
    uc_reg_write(e.uc,UC_ARM64_REG_Q0,vector); wrreg(e.uc,R_X0,99);
    assert(run_threads_once(&e)==1);
    assert(rdreg(e.uc,R_X0)==99 && rdreg(e.uc,UC_ARM64_REG_NZCV)==flags);
    uc_reg_read(e.uc,UC_ARM64_REG_Q0,restored); assert(!memcmp(vector,restored,16));
    assert(e.th[0].regs[0]==42);
    emu_free(&e);
    puts("PASS: GNU symbols/relocations, linker callbacks, streaming inflate, JNI fields, file mapping, thread/TLS, tracer/fork and register preservation");
    return 0;
}
