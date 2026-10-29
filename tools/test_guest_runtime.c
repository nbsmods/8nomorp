/* Focused regression tests for the offline guest libc/JNI fixture. */
#include "../src/ctxgen.c"
#include <assert.h>

int main(void){
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
    uc_close(e->uc);free(e);puts("guest runtime regression tests passed");return 0;
}
