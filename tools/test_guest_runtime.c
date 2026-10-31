/* Focused regression tests for the offline guest libc/JNI fixture. */
#include "../src/ctxgen.c"
#include <assert.h>

int main(void){
    uint8_t request[32];assert(!attest_hex("000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F",request));
    for(unsigned i=0;i<32;i++)assert(request[i]==i);
    assert(attest_hex("",request));assert(attest_hex("gg0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",request));
    uint8_t seed[8],again[8];assert(!attest_seed("deterministic",request,UINT64_MAX,seed));
    assert(!attest_seed("deterministic",request,UINT64_MAX,again));assert(!memcmp(seed,again,8));
    assert(!attest_seed("0102030405060708",request,0,seed));for(unsigned i=0;i<8;i++)assert(seed[i]==i+1);
    assert(attest_seed("bad",request,0,seed));assert(!attest_seed("random",request,0,seed));
    emu_t *e=calloc(1,sizeof *e);assert(e);
    assert(uc_open(UC_ARCH_ARM64,UC_MODE_LITTLE_ENDIAN,&e->uc)==UC_ERR_OK);
    assert(uc_mem_map(e->uc,0x10000,0x10000,UC_PROT_ALL)==UC_ERR_OK);
    guest_va_t ap={.stack=0x12000,.gr_top=0x13000,.gr_offs=-8};
    uint64_t pid=1234;char buffer[128];
    uc_mem_write(e->uc,0x12ff8,&pid,8);
    uc_mem_write(e->uc,0x11000,&ap,sizeof ap);
    uc_mem_write(e->uc,0x10000,"/proc/%i/status",16);
    assert(guest_vsnprintf(e,0x14000,sizeof buffer,0x10000,0x11000)==17);
    uc_mem_read(e->uc,0x14000,buffer,sizeof buffer);
    assert(!strcmp(buffer,"/proc/1234/status"));
    assert(guest_vsnprintf(e,0x14000,6,0x10000,0x11000)==17);
    uc_mem_read(e->uc,0x14000,buffer,6);assert(!strcmp(buffer,"/proc"));
    assert(guest_vsnprintf(e,0,0,0x10000,0x11000)==17);
    guest_va_t unchanged;uc_mem_read(e->uc,0x11000,&unchanged,sizeof unchanged);
    assert(!memcmp(&unchanged,&ap,sizeof ap));
    size_t length;e->tracer_pid=4096;
    const char *status=path_content(e,"/proc/1234/status",&length);
    assert(strstr(status,"TracerPid:\t4096\n"));
    assert(length==strlen(status));
    e->tracer_pid=0;status=path_content(e,"/proc/self/status",&length);
    assert(strstr(status,"TracerPid:\t0\n"));
    assert(path_content(e,"/proc/1234/task",&length)&&length==0);
    /* Older shields use scanf's auto-base %i for TracerPid. */
    write_cstr(e,0x10000,"TracerPid: 4096");write_cstr(e,0x10200,"TracerPid: %i");
    wrreg(e->uc,R_X2,0x10400);wrreg(e->uc,R_SP,0x18000);
    assert(emu_sscanf(e,0x10000,0x10200)==1);
    uint32_t parsed=0;uc_mem_read(e->uc,0x10400,&parsed,4);assert(parsed==4096);
    write_cstr(e,0x10000,"PPid: 500");assert(emu_sscanf(e,0x10000,0x10200)==0);
    write_cstr(e,0x10000,"TracerPid: 0x1000");assert(emu_sscanf(e,0x10000,0x10200)==1);
    uc_mem_read(e->uc,0x10400,&parsed,4);assert(parsed==4096);
    /* Decimal must stop at hex letters; %i retains octal/hex auto-base. */
    const char *inputs[]={"123abc", "077", "-42", "0Xff", "+", "xyz", "19"};
    const char *formats[]={"%d%c", "%i", "%d", "%i", "%u", "%x", "%1d%c"};
    const unsigned expected[]={123,63,(unsigned)-42,255,0,0,1};
    const int counts[]={2,1,1,1,0,0,2};
    for(unsigned i=0;i<sizeof inputs/sizeof inputs[0];i++){
        write_cstr(e,0x10000,inputs[i]);write_cstr(e,0x10200,formats[i]);
        wrreg(e->uc,R_X2,0x10400);wrreg(e->uc,UC_ARM64_REG_X3,0x10408);
        assert(emu_sscanf(e,0x10000,0x10200)==counts[i]);
        if(counts[i]){uc_mem_read(e->uc,0x10400,&parsed,4);assert(parsed==expected[i]);}
    }
    emu_t peer={0};e->peer=&peer;
    const char *shields[]={"libsupercell_brawlstars.so","libsupercell_clashofclans.so","libsupercell_clashroyale.so",
                          "libsupercell_moco.so","libsupercell_squad.so","libsupercell_hayday.so","libsupercell_boombeach.so"};
    for(unsigned i=0;i<sizeof shields/sizeof shields[0];i++){
        peer.image_name=shields[i];assert(guest_game(e)==&games[i]);
        const char *cmd=path_content(e,"/proc/self/cmdline",&length);
        assert(!strcmp(cmd,games[i].package));assert(length==strlen(cmd)+1);
    }
    e->peer=NULL;
    /* Direct variadic snprintf/asprintf must consume X registers correctly. */
    assert(!uc_mem_map(e->uc,MISC_BASE+0x805000,0x2000,UC_PROT_ALL));
    assert(!uc_mem_map(e->uc,HEAP_BASE,0x10000,UC_PROT_ALL));e->heap_next=HEAP_BASE;
    write_cstr(e,0x10000,"/proc/%i/status");
    wrreg(e->uc,R_X0,0x14000);wrreg(e->uc,R_X1,128);wrreg(e->uc,R_X2,0x10000);
    wrreg(e->uc,UC_ARM64_REG_X3,1234);wrreg(e->uc,R_X30,0x19000);
    dispatch_import(e,"snprintf");assert(rdreg(e->uc,R_X0)==17);
    uc_mem_read(e->uc,0x14000,buffer,sizeof buffer);assert(!strcmp(buffer,"/proc/1234/status"));
    wrreg(e->uc,R_X0,0x13000);wrreg(e->uc,R_X1,0x10000);wrreg(e->uc,R_X2,1234);
    dispatch_import(e,"asprintf");assert(rdreg(e->uc,R_X0)==17);
    uint64_t allocated=0;uc_mem_read(e->uc,0x13000,&allocated,8);
    uc_mem_read(e->uc,allocated,buffer,sizeof buffer);assert(!strcmp(buffer,"/proc/1234/status"));
    /* Byte-array JNI calls preserve bytes, slices, and direct element access. */
    wrreg(e->uc,R_X1,32);dispatch_import(e,"jni_176");uint64_t array=rdreg(e->uc,R_X0);assert(array);
    uint8_t sample[]={0,0x80,0xff,7},actual[4]={0};uc_mem_write(e->uc,0x14000,sample,4);
    wrreg(e->uc,R_X1,array);wrreg(e->uc,R_X2,3);wrreg(e->uc,UC_ARM64_REG_X3,4);wrreg(e->uc,UC_ARM64_REG_X4,0x14000);
    dispatch_import(e,"jni_208");uc_mem_read(e->uc,array+11,actual,4);assert(!memcmp(sample,actual,4));
    wrreg(e->uc,UC_ARM64_REG_X4,0x14100);dispatch_import(e,"jni_200");
    uc_mem_read(e->uc,0x14100,actual,4);assert(!memcmp(sample,actual,4));
    wrreg(e->uc,R_X2,0x14200);dispatch_import(e,"jni_184");assert(rdreg(e->uc,R_X0)==array+8);
    uint8_t copy=1;uc_mem_read(e->uc,0x14200,&copy,1);assert(!copy);
    wrreg(e->uc,R_X2,31);wrreg(e->uc,UC_ARM64_REG_X3,2);dispatch_import(e,"jni_200");assert(e->stop);e->stop=0;
    /* A main-thread condition wait must yield to a worker, not spin forever. */
    const uint32_t worker[]={0x52800021,0xb9000001,0xd65f03c0}; /* mov w1,1; str w1,[x0]; ret */
    uc_mem_write(e->uc,0x15000,worker,sizeof worker);
    uint32_t ready=0;uc_mem_write(e->uc,0x14000,&ready,4);
    e->nth=1;e->th[0].state=1;e->th[0].pc=0x15000;e->th[0].sp=0x18000;
    e->th[0].regs[0]=0x14000;e->th[0].regs[30]=SENT_THREAD;
    wrreg(e->uc,R_X30,0x19000);
    dispatch_import(e,"pthread_cond_timedwait");
    assert(e->yield_workers&&rdreg(e->uc,R_PC)==0x19000&&rdreg(e->uc,R_X0)==0);
    e->yield_workers=0;assert(run_threads_once(e));
    uc_mem_read(e->uc,0x14000,&ready,4);assert(ready==1);
    assert(rdreg(e->uc,R_PC)==0x19000&&rdreg(e->uc,R_X0)==0);
    assert(e->th[0].state==3);
    e->cur_ctx=1;dispatch_import(e,"pthread_cond_wait");assert(!e->yield_workers);
    e->strict_imports=1;e->stop=0;dispatch_import(e,"unknown_attestation_primitive");assert(e->stop);
    strcpy(e->natives[0].owner,"fixture/One");strcpy(e->natives[0].signature,"([B)[B");e->natives[0].function=0x1234;e->nnatives=1;
    uint64_t method=0;assert(!native_method(e,"fixture/One","([B)[B",&method)&&method==0x1234);
    assert(native_method(e,"fixture/Other","([B)[B",&method));e->natives[1]=e->natives[0];e->nnatives=2;
    assert(native_method(e,"fixture/One","([B)[B",&method));
    if(e->th[0].cpu)uc_context_free(e->th[0].cpu);
    uc_close(e->uc);free(e);puts("guest runtime regression tests passed");return 0;
}
