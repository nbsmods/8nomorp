/* Internal native-unpack implementation; included once by ctxgen.c.
 * Instruction-pattern discovery, followed by ABI/coverage checks.
 * Recognized protector routines do not guarantee arbitrary new schemes. */
#ifndef NATIVE_IMPL_H
#define NATIVE_IMPL_H
#include "lbts.h"
#include <fcntl.h>
#include <unistd.h>
#include <unicorn/arm.h>
#include <ctype.h>
#include <math.h>

static int native_blob(const char *path,uint8_t **data,size_t *length);
static int native_write_new(const char *path,const void *data,size_t length);
static const char *native_name(const char *path);

#define A32_STUB 0x20000000u
#define A32_STOP 0x2ffff000u
#define A32_THREAD_STOP 0x2fffe000u
#define A32_TLS  0x30000000u
#define A32_SP   0x40fff000u
#define A32_HEAP 0x50001000u
#define A32_LIMIT 0x60000000u
#define A32_VM 0x18000000u
#define A32_ENV 0x18001000u
#define A32_JNI 0x18002000u
#define A32_JVM 0x18003000u
#define A32_MAX_IMAGE (256u*1024*1024)
typedef struct { uint32_t va,off,filesz,memsz,flags; } a32_segment;
typedef struct {
    uint8_t *raw; size_t size; uint32_t bias,tags[64],symtab,strtab,nsyms,strsz;
    a32_segment seg[16]; unsigned nseg; const char *name;
} a32_image;
typedef struct { const uint8_t *data; size_t size,pos; int used,memory; } a32_file;
typedef struct {uint32_t address,size;uint8_t *data;} a32_memory;
typedef struct {uc_context *cpu;int active;uint32_t blocked,buffer,length,condition,wait_pid,wait_status,exit_status; a32_memory *memory;unsigned nmemory;} a32_thread;
typedef struct {uint8_t data[8192];unsigned size;uint32_t readfd,writefd;} a32_channel;
typedef struct {
    uc_engine *uc; a32_image shield,game; uint8_t *apk; size_t apk_size;
    struct apk_metadata metadata;
    char names[2048][1024]; unsigned nstub; uint32_t heap,keys[9][128],nextkey;
    uint32_t addresses[2048];
    uint32_t locale;
    struct {uint32_t address,size,capacity,owner;int used;} allocations[65536];unsigned nalloc;
    a32_file files[64]; char text[8192]; int failed,verbose;
    char file_paths[64][1024];
    uint8_t *file_owned[64];
    uint8_t libc[65536];size_t libc_size;
    a32_thread threads[8],main;unsigned nthread;int current;
    a32_channel channels[16];unsigned nchannel;
    uint8_t random[4096];
    uint32_t random_state;
    uint64_t clock_ns;
    uint32_t mmap_next;
    unsigned nsocket;
    uint8_t directory[128];
    uc_context *trace_cpu;a32_memory *trace_memory;unsigned trace_count;
    int trace_stopped,trace_pending;uint32_t trace_pid,trace_status,tracer_pid;
    struct {uint32_t guest;z_stream stream;int active;} inflaters[16];
    struct {uint32_t guest;uc_context *cpu;} jumps[16];unsigned njump;
    uint32_t handlers[65];
    struct {uint32_t id;uint64_t value;} fields[256];unsigned nfield;
    struct {uint32_t owner,name,signature,function;} natives[256];unsigned nnative;
    unsigned long calls;
} a32_runtime;

static uint16_t a32_u16(const uint8_t *p){return (uint16_t)(p[0]|p[1]<<8);}
static uint32_t a32_u32(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static void a32_p32(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static int a32_span(size_t size,uint32_t off,uint64_t n){return off<=size&&n<=size-off;}
static int a32_offset(const a32_image *m,uint32_t va,uint32_t n,uint32_t *off){
    for(unsigned i=0;i<m->nseg;i++){
        const a32_segment *s=&m->seg[i];
        if(va>=s->va&&va-s->va<=s->filesz&&n<=s->filesz-(va-s->va)){
            *off=s->off+va-s->va;return 0;
        }
    }return -1;
}
static int a32_parse(a32_image *m){
    const uint8_t *b=m->raw;
    if(m->size<52||memcmp(b,"\177ELF\1\1\1",7)||a32_u16(b+18)!=40||
       a32_u16(b+16)!=3||a32_u16(b+40)!=52||a32_u16(b+42)!=32)return -1;
    unsigned phnum=a32_u16(b+44);uint32_t phoff=a32_u32(b+28),dynamic=0,dynsize=0,gnu_hash=0;
    if(!phnum||phnum>128||!a32_span(m->size,phoff,(uint64_t)phnum*32))return -1;
    for(unsigned i=0;i<phnum;i++){
        const uint8_t *p=b+phoff+i*32;uint32_t type=a32_u32(p);
        if(type==2){dynamic=a32_u32(p+4);dynsize=a32_u32(p+16);}
        if(type!=1)continue;
        if(m->nseg==16)return -1;
        a32_segment *s=&m->seg[m->nseg++];
        *s=(a32_segment){a32_u32(p+8),a32_u32(p+4),a32_u32(p+16),a32_u32(p+20),a32_u32(p+24)};
        if(s->filesz>s->memsz||!a32_span(m->size,s->off,s->filesz)||
           (uint64_t)s->va+s->memsz+m->bias>0x18000000u||
           ((s->va-s->off)&4095))return -1;
    }
    if(!m->nseg||!dynsize||dynsize%8||!a32_span(m->size,dynamic,dynsize))return -1;
    int terminated=0;
    for(unsigned i=0;i<dynsize;i+=8){
        uint32_t tag=a32_u32(b+dynamic+i),value=a32_u32(b+dynamic+i+4);
        if(!tag){terminated=1;break;}
        if(tag<64)m->tags[tag]=value;
        if(tag==0x6ffffef5)gnu_hash=value;
        /* Android packed relocations and RELR need explicit decoding. */
        if(tag==0x6000000f||tag==0x60000011||tag==36)return -1;
    }
    if(!terminated||m->tags[7]||m->tags[8])return -1; /* ARM uses REL, not RELA. */
    m->symtab=m->tags[6];m->strtab=m->tags[5];m->strsz=m->tags[10];
    uint32_t hash;
    if(m->tags[4]&&!a32_offset(m,m->tags[4],8,&hash))m->nsyms=a32_u32(b+hash+4);
    else {
        if(!gnu_hash||a32_offset(m,gnu_hash,16,&hash))return -1;
        uint32_t buckets=a32_u32(b+hash),first=a32_u32(b+hash+4),bloom=a32_u32(b+hash+8);
        uint64_t bucket_va=(uint64_t)gnu_hash+16+(uint64_t)bloom*4,chain_va=bucket_va+(uint64_t)buckets*4;
        if(first>65536||buckets>65536||chain_va>UINT32_MAX||
           a32_offset(m,(uint32_t)bucket_va,buckets*4,&hash))return -1;
        uint32_t last=0;
        for(uint32_t i=0;i<buckets;i++){uint32_t index=a32_u32(b+hash+i*4);if(index&&index<first)return -1;if(index>last)last=index;}
        if(!last)m->nsyms=first;
        else for(uint32_t i=last;i<65536;i++){
            uint64_t va=chain_va+(uint64_t)(i-first)*4;
            if(va>UINT32_MAX||a32_offset(m,(uint32_t)va,4,&hash))return -1;
            if(a32_u32(b+hash)&1){m->nsyms=i+1;break;}
        }
    }
    uint32_t off;
    if(!m->nsyms||m->nsyms>65536||m->tags[11]!=16||
       a32_offset(m,m->symtab,m->nsyms*16,&off)||
       a32_offset(m,m->strtab,m->strsz,&off))return -1;
    return 0;
}
static const uint8_t *a32_symbol(const a32_image *m,unsigned index){
    uint32_t off;if(index>=m->nsyms||a32_offset(m,m->symtab+index*16,16,&off))return NULL;
    return m->raw+off;
}
static const char *a32_symname(const a32_image *m,unsigned index){
    const uint8_t *s=a32_symbol(m,index);uint32_t off;
    if(!s||a32_u32(s)>=m->strsz||a32_offset(m,m->strtab,m->strsz,&off))return NULL;
    const char *name=(const char *)m->raw+off+a32_u32(s);
    return memchr(name,0,m->strsz-a32_u32(s))?name:NULL;
}
static void a32_fail(a32_runtime *r,const char *what){
    if(!r->failed){uint32_t pc=0,lr=0;uc_reg_read(r->uc,UC_ARM_REG_PC,&pc);uc_reg_read(r->uc,UC_ARM_REG_LR,&lr);
        fprintf(stderr,"error: ARM32 %s (pc=0x%x lr=0x%x)\n",what,pc,lr);}
    r->failed=1;uc_emu_stop(r->uc);
}
static uint32_t a32_reg(a32_runtime *r,int reg){uint32_t v=0;if(uc_reg_read(r->uc,reg,&v))a32_fail(r,"register read");return v;}
static void a32_set(a32_runtime *r,int reg,uint32_t v){if(uc_reg_write(r->uc,reg,&v))a32_fail(r,"register write");}
static uint32_t a32_get(a32_runtime *r,uint32_t p){uint8_t b[4]={0};if(uc_mem_read(r->uc,p,b,4))a32_fail(r,"pointer read");return a32_u32(b);}
static void a32_put(a32_runtime *r,uint32_t p,uint32_t v){uint8_t b[4];a32_p32(b,v);if(uc_mem_write(r->uc,p,b,4))a32_fail(r,"pointer write");}
static uint32_t a32_alloc(a32_runtime *r,uint32_t n){
    uint32_t p=r->heap;uint64_t size=((uint64_t)n+15)&~15ULL;if(!size)size=16;
    uint32_t owner=r->current>=0&&r->threads[r->current].memory?(uint32_t)r->current+1:0;
    unsigned best=r->nalloc;
    for(unsigned i=0;i<r->nalloc;i++)if(!r->allocations[i].used&&r->allocations[i].owner==owner&&r->allocations[i].capacity>=size&&
        (best==r->nalloc||r->allocations[i].capacity<r->allocations[best].capacity))best=i;
    if(best<r->nalloc){r->allocations[best].used=1;r->allocations[best].size=n;return r->allocations[best].address;}
    if(size>A32_LIMIT-p||r->nalloc==65536){a32_fail(r,"heap exhausted");return 0;}
    r->allocations[r->nalloc].address=p;r->allocations[r->nalloc].size=n;r->allocations[r->nalloc].capacity=(uint32_t)size;
    r->allocations[r->nalloc].owner=owner;r->allocations[r->nalloc++].used=1;
    r->heap+=(uint32_t)size;return p;
}
static void a32_release(a32_runtime *r,uint32_t p){
    if(!p)return;
    uint32_t owner=r->current>=0&&r->threads[r->current].memory?(uint32_t)r->current+1:0;
    for(unsigned i=0;i<r->nalloc;i++)if(r->allocations[i].address==p&&r->allocations[i].owner==owner){r->allocations[i].used=0;return;}
}
static void a32_zero(a32_runtime *r,uint32_t p,uint32_t length){
    uint8_t zeros[4096]={0};
    for(uint32_t i=0;i<length;){uint32_t n=length-i<sizeof zeros?length-i:sizeof zeros;
        if(uc_mem_write(r->uc,(uint64_t)p+i,zeros,n)){a32_fail(r,"zero allocation");return;}i+=n;}
}
static int a32_string(a32_runtime *r,uint32_t p,char *out,size_t cap){
    if(!p||!cap)return -1;
    for(size_t i=0;i<cap;i++){
        if(uc_mem_read(r->uc,(uint64_t)p+i,out+i,1)){a32_fail(r,"string read");return -1;}
        if(!out[i])return 0;
    }out[cap-1]=0;a32_fail(r,"unterminated string");return -1;
}
static uint32_t a32_cstr(a32_runtime *r,const char *text){uint32_t p=a32_alloc(r,(uint32_t)strlen(text)+1);if(p&&uc_mem_write(r->uc,p,text,strlen(text)+1))a32_fail(r,"string write");return p;}
static uint32_t a32_stub(a32_runtime *r,const char *name){
    for(unsigned i=0;i<r->nstub;i++)if(!strcmp(name,r->names[i]))return r->addresses[i];
    if(r->nstub==2048||strlen(name)>=sizeof r->names[0]){a32_fail(r,"stub limit");return 0;}
    unsigned i=r->nstub++;strcpy(r->names[i],name);uint32_t address=A32_STUB+i*16;
    if(!strcmp(name,"__progname")){address=a32_alloc(r,4);a32_put(r,address,a32_cstr(r,r->metadata.package));}
    else if(!strcmp(name,"__stack_chk_guard")){address=a32_alloc(r,4);a32_put(r,address,0x12345678);}
    else if(!strcmp(name,"environ")){address=a32_alloc(r,8);a32_put(r,address,address+4);}
    else if(!strcmp(name,"__sF"))address=a32_alloc(r,3*84);
    else a32_put(r,address,0xe12fff1e);
    r->addresses[i]=address;return address;
}
static uint32_t a32_export(const a32_image *m,const char *name){
    for(unsigned i=0;i<m->nsyms;i++){
        const char *n=a32_symname(m,i);const uint8_t *s=a32_symbol(m,i);
        if(n&&!strcmp(n,name)&&a32_u16(s+14))return m->bias+a32_u32(s+4);
    }return 0;
}
static int a32_libc(a32_runtime *r){
    static const char *exports[]={"read","open","exit","malloc","mmap","munmap","free","close","lseek","mprotect","sysconf","strstr","cacheflush","__system_property_get","dladdr","execl","inotify_add_watch","syscall","dl_iterate_phdr","dlopen","eventfd","inotify_init","fork","prctl","killpg","fgets","fopen","sscanf","fclose"};
    uint8_t *b=r->libc;unsigned n=sizeof exports/sizeof exports[0];
    memcpy(b,"\177ELF\1\1\1",7);b[16]=3;b[18]=40;b[20]=1;b[40]=52;b[42]=32;
    a32_p32(b+32,0x8000);b[46]=40;b[48]=5;b[50]=1;
    const char names[]="\0.shstrtab\0.dynsym\0.dynstr\0.text\0";memcpy(b+0x100,names,sizeof names);
    uint32_t string=0x2001;
    for(unsigned i=0;i<n;i++){
        uint8_t *s=b+0x1000+(i+1)*16;a32_p32(s,string-0x2000);
        a32_p32(s+4,a32_stub(r,exports[i])-0x10000000u);a32_p32(s+8,16);s[12]=0x12;s[14]=4;
        size_t len=strlen(exports[i])+1;memcpy(b+string,exports[i],len);string+=(uint32_t)len;
    }
    uint32_t fields[4][10]={{1,3,0,0,0x100,sizeof names,0,0,1,0},
        {11,11,2,0x1000,0x1000,(n+1)*16,3,1,4,16},
        {19,3,2,0x2000,0x2000,string-0x2000,0,0,1,0},
        {27,1,6,0x3000,0x3000,4,0,0,4,0}};
    for(unsigned i=0;i<4;i++)for(unsigned j=0;j<10;j++)a32_p32(b+0x8000+(i+1)*40+j*4,fields[i][j]);
    a32_p32(b+0x3000,0xe12fff1e);r->libc_size=0x8000+5*40;
    if(uc_mem_map(r->uc,0x10000000,0x10000,UC_PROT_ALL)||uc_mem_write(r->uc,0x10000000,b,r->libc_size))return -1;
    return r->failed?-1:0;
}
static int a32_map(a32_runtime *r,a32_image *m){
    uint64_t starts[16],ends[16];unsigned count=0;
    for(unsigned i=0;i<m->nseg;i++){
        a32_segment *s=&m->seg[i];uint64_t start=(m->bias+s->va)&~4095u,end=((uint64_t)m->bias+s->va+s->memsz+4095)&~4095ULL;
        if(start==end)continue;
        for(unsigned j=0;j<count;){
            if(start<=ends[j]&&end>=starts[j]){
                if(starts[j]<start)start=starts[j];
                if(ends[j]>end)end=ends[j];
                --count;starts[j]=starts[count];ends[j]=ends[count];j=0;
            }else j++;
        }
        starts[count]=start;ends[count++]=end;
    }
    for(unsigned i=0;i<count;i++)if(uc_mem_map(r->uc,starts[i],ends[i]-starts[i],UC_PROT_ALL))return -1;
    for(unsigned i=0;i<m->nseg;i++){
        a32_segment *s=&m->seg[i];
        if(s->filesz&&uc_mem_write(r->uc,m->bias+s->va,m->raw+s->off,s->filesz))return -1;
    }return 0;
}
static int a32_relocate(a32_runtime *r,a32_image *m){
    uint32_t tables[]={m->tags[17],m->tags[23]},sizes[]={m->tags[18],m->tags[2]};
    if((sizes[0]&&m->tags[19]!=8)||(sizes[1]&&m->tags[20]!=17))return -1;
    for(unsigned t=0;t<2;t++){
        uint32_t off;if(!sizes[t])continue;
        if(sizes[t]%8||a32_offset(m,tables[t],sizes[t],&off))return -1;
        for(uint32_t i=0;i<sizes[t];i+=8){
            uint32_t address=a32_u32(m->raw+off+i),info=a32_u32(m->raw+off+i+4),type=info&255,index=info>>8;
            if(!type)continue;
            int backed=0;for(unsigned j=0;j<m->nseg;j++){a32_segment *s=&m->seg[j];if(address>=s->va&&address-s->va<=s->memsz&&4<=s->memsz-(address-s->va))backed=1;}
            if(!backed)return -1;
            uint32_t addend=a32_get(r,m->bias+address),value=0;
            if(type==23){if(index)return -1;value=m->bias+addend;}
            else if(type==2||type==21||type==22){
                const uint8_t *sym=a32_symbol(m,index);const char *name=a32_symname(m,index);if(!sym||!name)return -1;
                if(a32_u16(sym+14))value=a32_u32(sym+4)+(a32_u16(sym+14)==0xfff1?0:m->bias);
                else if(*name){value=a32_export(m==&r->game?&r->shield:&r->game,name);if(!value)value=a32_stub(r,name);}
                if(type==2)value+=addend;
            }else {fprintf(stderr,"error: unsupported ARM relocation %u\n",type);return -1;}
            a32_put(r,m->bias+address,value);
        }
    }return r->failed?-1:0;
}
static void a32_return(a32_runtime *r,uint32_t v){a32_set(r,UC_ARM_REG_R0,v);a32_set(r,UC_ARM_REG_PC,a32_reg(r,UC_ARM_REG_LR));}
static a32_file *a32_file_at(a32_runtime *r,uint32_t fd){return fd>=0x200&&fd<0x240&&r->files[fd-0x200].used?&r->files[fd-0x200]:NULL;}
static uint32_t a32_open(a32_runtime *r,uint32_t path){
    char name[1024];if(a32_string(r,path,name,sizeof name))return UINT32_MAX;
    if(r->verbose)fprintf(stderr,"    [arm32 path] %s\n",name);
    const uint8_t *data=NULL;size_t size=0;
    int memory=strstr(name,"/proc/")&&strstr(name,"/mem");
    if(memory){size=UINT32_MAX;}
    else if(!strcmp(name,"/proc/self/task")||!strcmp(name,"/proc/1234/task")){data=r->directory;size=80;}
    else if(strstr(name,"/task/1234/comm")){
        const char *comm=strrchr(r->metadata.package,'.');comm=comm?comm+1:r->metadata.package;
        snprintf(r->text,sizeof r->text,"%s\n",comm);data=(const uint8_t *)r->text;size=strlen(r->text);
    }
    else if(!strcmp(name,"/proc/self/cmdline")){data=(const uint8_t *)r->metadata.package;size=strlen(r->metadata.package)+1;}
    else if(!strcmp(name,"/proc/sys/kernel/yama/ptrace_scope")){data=(const uint8_t *)"0\n";size=2;}
    else if(!strcmp(name,"/dev/urandom")||!strcmp(name,"/dev/random")){data=r->random;size=sizeof r->random;}
    else if(strstr(name,"/libc.so")){data=r->libc;size=r->libc_size;}
    else if(strstr(name,"/base.apk")){data=r->apk;size=r->apk_size;}
    else if(strstr(name,r->shield.name)){data=r->shield.raw;size=r->shield.size;}
    else if(strstr(name,r->game.name)){data=r->game.raw;size=r->game.size;}
    else if(!strcmp(name,"/proc/self/status")||!strcmp(name,"/proc/1234/status")){
        snprintf(r->text,sizeof r->text,"Name:\t%s\nState:\tR (running)\nTgid:\t1234\nPid:\t1234\nPPid:\t1\nTracerPid:\t%u\nUid:\t10000\t10000\t10000\t10000\n",r->metadata.package,r->tracer_pid);
        data=(const uint8_t *)r->text;size=strlen(r->text);
    }else if(strstr(name,"/maps")){
        size_t used=0;
        for(unsigned k=0;k<2;k++){a32_image *m=k?&r->game:&r->shield;
            for(unsigned i=0;i<m->nseg;i++){a32_segment *s=&m->seg[i];
                int n=snprintf(r->text+used,sizeof r->text-used,"%08x-%08x %c%c%cp %08x 00:00 %u /data/app/%s/lib/arm/%s\n",
                    (m->bias+s->va)&~4095u,(m->bias+s->va+s->memsz+4095)&~4095u,
                    s->flags&4?'r':'-',s->flags&2?'w':'-',s->flags&1?'x':'-',s->off&~4095u,k+1,r->metadata.package,m->name);
                if(n<0||(size_t)n>=sizeof r->text-used){a32_fail(r,"maps size");return UINT32_MAX;}used+=(size_t)n;
            }
        }
        snprintf(r->text+used,sizeof r->text-used,"10000000-10010000 r-xp 00000000 00:01 999 /system/lib/libc.so\n40000000-41000000 rw-p 00000000 00:00 0 [stack]\n");
        data=(const uint8_t *)r->text;size=strlen(r->text);
    }else return UINT32_MAX;
    for(unsigned i=0;i<64;i++)if(!r->files[i].used){
        free(r->file_owned[i]);r->file_owned[i]=NULL;
        if(data==(const uint8_t *)r->text){
            uint8_t *copy=malloc(size?size:1);if(!copy)return UINT32_MAX;memcpy(copy,data,size);r->file_owned[i]=copy;data=copy;
        }
        r->files[i]=(a32_file){data,size,0,1,memory};strcpy(r->file_paths[i],name);return 0x200+i;
    }
    return UINT32_MAX;
}
static int a32_trace_access(a32_runtime *r,uint32_t address,void *buffer,size_t length,int write);
static uint32_t a32_read(a32_runtime *r,a32_file *f,uint32_t dest,uint32_t n){
    if(!f)return UINT32_MAX;
    if(n>f->size-f->pos)n=(uint32_t)(f->size-f->pos);
    if(f->memory){if(n>A32_MAX_IMAGE)return UINT32_MAX;uint8_t *buf=malloc(n?n:1);if(!buf)return UINT32_MAX;
        int err=a32_trace_access(r,(uint32_t)f->pos,buf,n,0)||uc_mem_write(r->uc,dest,buf,n);free(buf);if(err)return UINT32_MAX;f->pos+=n;return n;}
    if(n&&uc_mem_write(r->uc,dest,f->data+f->pos,n)){a32_fail(r,"file read");return UINT32_MAX;}f->pos+=n;return n;
}
static uint32_t a32_mmap(a32_runtime *r,uint32_t address,uint32_t size,uint32_t flags,uint32_t fd,uint64_t offset){
    if(!size||size>A32_MAX_IMAGE||(offset&4095))return (uint32_t)-22;
    uint32_t length=(size+4095)&~4095u;
    if(!(flags&0x10)){address=r->mmap_next;if((uint64_t)address+length>0x78000000)return (uint32_t)-12;}
    if(address&4095||(uint64_t)address+length>UINT32_MAX)return (uint32_t)-22;
    a32_file *file=NULL;
    if(!(flags&0x20)){file=a32_file_at(r,fd);if(!file||file->memory||offset>file->size)return (uint32_t)-9;}
    if(uc_mem_map(r->uc,address,length,UC_PROT_ALL))return (uint32_t)-12;
    if(file){size_t n=file->size-(size_t)offset;if(n>size)n=size;
        if(n&&uc_mem_write(r->uc,address,file->data+offset,n)){uc_mem_unmap(r->uc,address,length);return (uint32_t)-14;}}
    if(!(flags&0x10))r->mmap_next=address+length;
    return address;
}
static void a32_memory_free(a32_memory *memory,unsigned count){if(memory){for(unsigned i=0;i<count;i++)free(memory[i].data);free(memory);}}
static a32_memory *a32_snapshot(a32_runtime *r,unsigned *count){
    a32_memory *memory=calloc(36,sizeof *memory);unsigned n=0;if(!memory)return NULL;
    for(unsigned k=0;k<2;k++){a32_image *m=k?&r->game:&r->shield;
        for(unsigned i=0;i<m->nseg;i++)if(m->seg[i].flags&2)memory[n++]=(a32_memory){m->bias+m->seg[i].va,m->seg[i].memsz,NULL};
    }
    memory[n++]=(a32_memory){0x50000000,r->heap-0x50000000,NULL};
    memory[n++]=(a32_memory){0x40000000,0x1000000,NULL};
    memory[n++]=(a32_memory){A32_TLS,0x10000,NULL};
    for(unsigned i=0;i<n;i++){
        memory[i].data=malloc(memory[i].size?memory[i].size:1);
        if(!memory[i].data||uc_mem_read(r->uc,memory[i].address,memory[i].data,memory[i].size)){a32_memory_free(memory,n);return NULL;}
    }*count=n;return memory;
}
static void a32_restore(a32_runtime *r,a32_memory *memory,unsigned count){
    for(unsigned i=0;i<count;i++)if(uc_mem_write(r->uc,memory[i].address,memory[i].data,memory[i].size))a32_fail(r,"fork memory restore");
}
static int a32_fork(a32_runtime *r){
    if(r->nthread==8)return -1;
    a32_thread *t=&r->threads[r->nthread];
    t->memory=a32_snapshot(r,&t->nmemory);if(!t->memory)return -1;
    uint32_t result=a32_reg(r,UC_ARM_REG_R0),pc=a32_reg(r,UC_ARM_REG_PC)|((a32_reg(r,UC_ARM_REG_CPSR)&32)?1u:0u);
    a32_set(r,UC_ARM_REG_R0,0);a32_set(r,UC_ARM_REG_PC,a32_reg(r,UC_ARM_REG_LR));
    if(uc_context_alloc(r->uc,&t->cpu)||uc_context_save(r->uc,t->cpu)){a32_fail(r,"fork context");return -1;}
    a32_set(r,UC_ARM_REG_R0,result);a32_set(r,UC_ARM_REG_PC,pc);t->active=1;r->nthread++;return 2000+(int)r->nthread;
}
static int a32_trace_access(a32_runtime *r,uint32_t address,void *buffer,size_t length,int write){
    for(unsigned i=0;i<r->trace_count;i++){a32_memory *m=&r->trace_memory[i];
        if(address>=m->address&&address-m->address<=m->size&&length<=m->size-(address-m->address)){
            if(write)memcpy(m->data+address-m->address,buffer,length);else memcpy(buffer,m->data+address-m->address,length);return 0;
        }
    }return write?uc_mem_write(r->uc,address,buffer,length):uc_mem_read(r->uc,address,buffer,length);
}
static int a32_trace_reg(unsigned i){return i<13?UC_ARM_REG_R0+(int)i:i==13?UC_ARM_REG_SP:i==14?UC_ARM_REG_LR:i==15?UC_ARM_REG_PC:UC_ARM_REG_CPSR;}
/* Unicorn 2.1.4's ARM context PC/CPSR writers access live CPU state. Use the
 * public live-register API while preserving the currently scheduled task. */
static int a32_context_write(a32_runtime *r,uc_context *context,int reg,uint32_t value){
    uc_context *saved=NULL;if(uc_context_alloc(r->uc,&saved))return -1;
    int err=uc_context_save(r->uc,saved)||uc_context_restore(r->uc,context)||
        uc_reg_write(r->uc,reg,&value)||uc_context_save(r->uc,context);
    if(uc_context_restore(r->uc,saved))err=1;
    uc_context_free(saved);return err?-1:0;
}
static int a32_deliver(a32_runtime *r,uc_context *context,uint32_t signal){
    uint32_t info=0x18010000,frame=0x18010100;
    uint8_t siginfo[128]={0},ucontext[256]={0};a32_p32(siginfo,signal);a32_p32(siginfo+8,1);
    for(unsigned i=0;i<17;i++){uint32_t value=0;if(uc_context_reg_read(context,a32_trace_reg(i),&value))return -1;a32_p32(ucontext+32+i*4,value);}
    a32_p32(siginfo+12,a32_u32(ucontext+92));
    if(uc_mem_write(r->uc,info,siginfo,sizeof siginfo)||uc_mem_write(r->uc,frame,ucontext,sizeof ucontext))return -1;
    return a32_context_write(r,context,UC_ARM_REG_PC,r->handlers[signal])||
        a32_context_write(r,context,UC_ARM_REG_R0,signal)||a32_context_write(r,context,UC_ARM_REG_R1,info)||
        a32_context_write(r,context,UC_ARM_REG_R2,frame)||a32_context_write(r,context,UC_ARM_REG_LR,a32_stub(r,"emu_signal_return"));
}
static int32_t a32_ptrace(a32_runtime *r,uint32_t request,uint32_t pid,uint32_t address,uint32_t data){
    if(request==16){if(pid!=1234)return -3;r->trace_pid=pid;r->tracer_pid=r->current>=0?2001+r->current:1234;r->trace_pending=r->trace_stopped=1;r->trace_status=(19u<<8)|0x7f;return 0;}
    if(!r->trace_pid||pid!=r->trace_pid)return -3;
    if(request==7||request==17){
        if(r->verbose&&data)fprintf(stderr,"    [arm32 signal] %u handler=%x saved=%d\n",data,data<=64?r->handlers[data]:0,r->trace_cpu!=NULL);
        if(data&&data<=64&&r->handlers[data]>1&&r->trace_cpu){
            if(a32_deliver(r,r->trace_cpu,data))return -5;
        }
        r->trace_stopped=0;if(request==17)r->trace_pid=r->tracer_pid=0;return 0;
    }
    if(request==0x4200)return 0;
    if(request==0x4202){
        uint8_t info[128]={0};uint32_t signo=(r->trace_status>>8)&255,pc=0;
        if(r->trace_cpu)uc_context_reg_read(r->trace_cpu,UC_ARM_REG_PC,&pc);
        a32_p32(info,signo);a32_p32(info+8,1);a32_p32(info+12,pc);
        return uc_mem_write(r->uc,data,info,sizeof info)?-14:0;
    }
    if(request>=1&&request<=6){uint8_t word[4];
        if(request<=3){if(a32_trace_access(r,address,word,4,0))return -5;return uc_mem_write(r->uc,data,word,4)?-14:0;}
        a32_p32(word,data);return a32_trace_access(r,address,word,4,1)?-5:0;
    }
    if(request==12||request==13||request==0x4204||request==0x4205){
        if(!r->trace_cpu)return -5;
        int write=request==13||request==0x4205;uint32_t dest=data,length=72;uint8_t regs[72]={0};
        if(request>=0x4204){if(address!=1)return -5;dest=a32_get(r,data);length=a32_get(r,data+4);if(length>72)length=72;}
        if(write){if(uc_mem_read(r->uc,dest,regs,length))return -14;
            for(unsigned i=0;i<length/4&&i<17;i++){uint32_t v=a32_u32(regs+i*4);if(a32_context_write(r,r->trace_cpu,a32_trace_reg(i),v))return -5;}
        }else{
            for(unsigned i=0;i<17;i++){uint32_t v=0;if(uc_context_reg_read(r->trace_cpu,a32_trace_reg(i),&v))return -5;a32_p32(regs+i*4,v);}
            if(uc_mem_write(r->uc,dest,regs,length))return -14;
        }
        if(request>=0x4204)a32_put(r,data+4,length);
        return 0;
    }return -5;
}
static int a32_spawn(a32_runtime *r,uint32_t output,uint32_t entry,uint32_t argument){
    if(r->nthread==8)return 11;
    uc_context *saved=NULL;unsigned i=r->nthread; a32_thread *t=&r->threads[i];
    if(uc_context_alloc(r->uc,&saved)||uc_context_save(r->uc,saved)||uc_context_alloc(r->uc,&t->cpu)){if(saved)uc_context_free(saved);return 12;}
    for(unsigned j=0;j<13;j++)a32_set(r,UC_ARM_REG_R0+(int)j,0);
    a32_set(r,UC_ARM_REG_R0,argument);a32_set(r,UC_ARM_REG_SP,0x421ff000+i*0x200000);
    a32_set(r,UC_ARM_REG_LR,A32_THREAD_STOP);a32_set(r,UC_ARM_REG_PC,entry);
    int err=uc_context_save(r->uc,t->cpu);uc_context_restore(r->uc,saved);uc_context_free(saved);
    if(err){uc_context_free(t->cpu);t->cpu=NULL;return 12;}
    t->active=1;r->nthread++;a32_put(r,output,i+1);return 0;
}
static uint32_t a32_arg(a32_runtime *r,unsigned index){
    return index<4?a32_reg(r,UC_ARM_REG_R0+(int)index):a32_get(r,a32_reg(r,UC_ARM_REG_SP)+(index-4)*4);
}
typedef struct {unsigned index;uint32_t va;int memory;} a32_arguments;
static uint32_t a32_next(a32_runtime *r,a32_arguments *args){
    if(args->memory){uint32_t value=a32_get(r,args->va);args->va+=4;return value;}
    return a32_arg(r,args->index++);
}
static int a32_format(a32_runtime *r,char *output,size_t capacity,const char *format,a32_arguments args){
    size_t used=0;
    for(const char *p=format;*p;){
        if(*p!='%'){if(used+1>=capacity)return -1;output[used++]=*p++;continue;}p++;
        if(*p=='%'){if(used+1>=capacity)return -1;output[used++]='%';p++;continue;}
        char spec[64]="%";size_t n=1;
        while(*p&&strchr("-+ #0",*p)){if(n>10)return -1;spec[n++]=*p++;}
        unsigned width=0;
        if(*p=='*'){width=a32_next(r,&args);p++;if(width>8192)return -1;}
        else while(isdigit((unsigned char)*p)){width=width*10+(unsigned)(*p++-'0');if(width>8192)return -1;}
        if(width)n+=(size_t)snprintf(spec+n,sizeof spec-n,"%u",width);
        if(*p=='.'){p++;unsigned precision=0;
            if(*p=='*'){precision=a32_next(r,&args);p++;if(precision>8192)return -1;}
            else while(isdigit((unsigned char)*p)){precision=precision*10+(unsigned)(*p++-'0');if(precision>8192)return -1;}
            n+=(size_t)snprintf(spec+n,sizeof spec-n,".%u",precision);
        }
        unsigned longs=0;while(*p=='l'){longs++;p++;}if(*p=='z'||*p=='t'){p++;longs=1;}
        char kind=*p++;if(!kind)return -1;int length;
        if(kind=='s'){
            uint32_t ptr=a32_next(r,&args);char text[8192];
            if(ptr){if(a32_string(r,ptr,text,sizeof text))return -1;}else strcpy(text,"(null)");
            spec[n++]='s';spec[n]=0;length=snprintf(output+used,capacity-used,spec,text);
        }else if(kind=='c'){
            spec[n++]='c';spec[n]=0;length=snprintf(output+used,capacity-used,spec,(int)a32_next(r,&args));
        }else if(strchr("diuoxXp",kind)){
            if(kind=='p'){kind='x';if(used+2>=capacity)return -1;output[used++]='0';output[used++]='x';}
            uint64_t value;
            if(longs>1){if(args.memory)args.va=(args.va+7)&~7u;else args.index=(args.index+1)&~1u;
                value=a32_next(r,&args);value|=(uint64_t)a32_next(r,&args)<<32;
            }else {uint32_t word=a32_next(r,&args);value=kind=='d'||kind=='i'?(uint64_t)(int64_t)(int32_t)word:word;}
            spec[n++]='l';spec[n++]='l';spec[n++]=kind;spec[n]=0;
            if(kind=='d'||kind=='i')length=snprintf(output+used,capacity-used,spec,(long long)value);
            else length=snprintf(output+used,capacity-used,spec,(unsigned long long)value);
        }else return -1;
        if(length<0||(size_t)length>=capacity-used)return -1;
        used+=(size_t)length;
    }output[used]=0;return (int)used;
}
static int a32_sscanf(a32_runtime *r,const char *text,const char *format){
    const char *p=text,*f=format;unsigned arg=2;int assigned=0;
    while(*f){
        if(isspace((unsigned char)*f)){while(isspace((unsigned char)*p))p++;f++;continue;}
        if(*f!='%'){if(*p!=*f)break;p++;f++;continue;}f++;
        if(*f=='%'){if(*p!='%')break;p++;f++;continue;}
        int suppress=*f=='*';if(suppress)f++;
        unsigned width=0;while(isdigit((unsigned char)*f))width=width*10+(unsigned)(*f++-'0');
        if(!width)width=8191;
        unsigned longs=0;while(*f=='l'){longs++;f++;}
        char kind=*f++;uint32_t dest=suppress?0:a32_arg(r,arg++);
        if(kind!='c'&&kind!='['&&kind!='n')while(isspace((unsigned char)*p))p++;
        if(kind=='n'){if(!suppress)a32_put(r,dest,(uint32_t)(p-text));continue;}
        if(!*p)break;
        if(strchr("duxXoi",kind)){
            char buf[8192];size_t n=strlen(p);if(n>width)n=width;if(n>8191)n=8191;memcpy(buf,p,n);buf[n]=0;
            char *end;int base=kind=='x'||kind=='X'?16:kind=='o'?8:kind=='i'?0:10;
            unsigned long long value=kind=='d'||kind=='i'?(unsigned long long)strtoll(buf,&end,base):strtoull(buf,&end,base);
            if(end==buf)break;
            p+=end-buf;
            if(!suppress){a32_put(r,dest,(uint32_t)value);if(longs>1)a32_put(r,dest+4,(uint32_t)(value>>32));assigned++;}
        }else if(kind=='s'||kind=='c'||kind=='['){
            uint8_t allowed[256]={0};int inverse=0;
            if(kind=='['){if(*f=='^'){inverse=1;f++;}if(*f==']')allowed[(unsigned char)*f++]=1;
                while(*f&&*f!=']'){unsigned lo=(unsigned char)*f++;if(*f=='-'&&f[1]&&f[1]!=']'){unsigned hi=(unsigned char)f[1];f+=2;for(unsigned ch=lo;ch<=hi;ch++)allowed[ch]=1;}else allowed[lo]=1;}if(*f!=']')break;f++;}
            unsigned n=0;if(kind=='c'&&width==8191)width=1;
            while(p[n]&&n<width&&(kind=='c'||(kind=='s'?!isspace((unsigned char)p[n]):!!allowed[(unsigned char)p[n]]!=inverse)))n++;
            if(!n)break;
            if(!suppress){if(uc_mem_write(r->uc,dest,p,n))a32_fail(r,"sscanf string");if(kind!='c'){uint8_t z=0;if(uc_mem_write(r->uc,dest+n,&z,1))a32_fail(r,"sscanf terminator");}assigned++;}p+=n;
        }else {a32_fail(r,"unsupported sscanf conversion");break;}
    }return assigned;
}
static void a32_import(uc_engine *uc,uint64_t pc,uint32_t width,void *user){
    a32_runtime *r=user;(void)uc;(void)width;
    if(pc>=A32_STOP&&pc<A32_STOP+4096){
        if(pc!=A32_STOP)a32_fail(r,"invalid return sentinel");else uc_emu_stop(r->uc);
        return;
    }
    if(pc<A32_STUB||pc>=A32_STUB+r->nstub*16||(pc-A32_STUB)%16){a32_fail(r,"invalid import address");return;}
    const char *name=r->names[(pc-A32_STUB)/16];
    uint32_t a=a32_reg(r,UC_ARM_REG_R0),b=a32_reg(r,UC_ARM_REG_R1),c=a32_reg(r,UC_ARM_REG_R2),d=a32_reg(r,UC_ARM_REG_R3);
    char x[8192],y[8192];uint32_t v=0;
    if(r->verbose&&r->calls++<50000)fprintf(stderr,"    [arm32] %s %x %x %x %x lr=%x\n",name,a,b,c,d,a32_reg(r,UC_ARM_REG_LR));
#define IS(s) (!strcmp(name,s))
#define RETURN(value) do { a32_return(r,(uint32_t)(value));return; } while(0)
    if(IS("emu_signal_return")){
        uint32_t frame=0x18010100,psr=a32_get(r,frame+96),pc=a32_get(r,frame+92);
        for(unsigned i=0;i<15;i++)a32_set(r,a32_trace_reg(i),a32_get(r,frame+32+i*4));
        a32_set(r,UC_ARM_REG_CPSR,psr);a32_set(r,UC_ARM_REG_PC,pc|((psr&32)?1u:0u));return;
    }
    if(IS("crc32")||IS("adler32")){
        uLong sum=a;uint8_t buf[16384];if(!b)RETURN(IS("crc32")?crc32(0,NULL,0):adler32(0,NULL,0));
        while(c){uint32_t n=c<sizeof buf?c:sizeof buf;if(uc_mem_read(r->uc,b,buf,n)){a32_fail(r,"checksum read");return;}
            sum=IS("crc32")?crc32(sum,buf,n):adler32(sum,buf,n);b+=n;c-=n;}RETURN(sum);
    }
    if(IS("inflateInit2_")||IS("inflateInit_")){
        if((IS("inflateInit2_")?d:c)!=56)RETURN(Z_VERSION_ERROR);
        for(unsigned i=0;i<16;i++)if(!r->inflaters[i].active){
            memset(&r->inflaters[i].stream,0,sizeof(z_stream));int result=inflateInit2(&r->inflaters[i].stream,IS("inflateInit2_")?(int)b:MAX_WBITS);
            if(result!=Z_OK)RETURN(result);
            r->inflaters[i].guest=a;r->inflaters[i].active=1;a32_put(r,a+28,1);RETURN(Z_OK);
        }RETURN(Z_MEM_ERROR);
    }
    if(IS("inflate")||IS("inflateEnd")){
        unsigned i;for(i=0;i<16;i++)if(r->inflaters[i].active&&r->inflaters[i].guest==a)break;
        if(i==16)RETURN(Z_STREAM_ERROR);
        z_stream *z=&r->inflaters[i].stream;
        if(IS("inflateEnd")){int result=inflateEnd(z);r->inflaters[i].active=0;a32_put(r,a+28,0);RETURN(result);}
        uint32_t in=a32_get(r,a),nin=a32_get(r,a+4),out=a32_get(r,a+12),nout=a32_get(r,a+16);
        if(nin>A32_MAX_IMAGE||nout>A32_MAX_IMAGE)RETURN(Z_MEM_ERROR);
        uint8_t *input=malloc(nin?nin:1),*output=malloc(nout?nout:1);
        if(!input||!output){free(input);free(output);RETURN(Z_MEM_ERROR);}
        if(nin&&uc_mem_read(r->uc,in,input,nin)){free(input);free(output);RETURN(Z_STREAM_ERROR);}
        z->next_in=input;z->avail_in=nin;z->next_out=output;z->avail_out=nout;int result=inflate(z,(int)b);
        uint32_t produced=nout-z->avail_out;
        if(produced&&uc_mem_write(r->uc,out,output,produced))result=Z_STREAM_ERROR;
        a32_put(r,a,in+nin-z->avail_in);a32_put(r,a+4,z->avail_in);a32_put(r,a+8,(uint32_t)z->total_in);
        a32_put(r,a+12,out+produced);a32_put(r,a+16,z->avail_out);a32_put(r,a+20,(uint32_t)z->total_out);
        a32_put(r,a+44,(uint32_t)z->data_type);a32_put(r,a+48,(uint32_t)z->adler);
        z->next_in=NULL;z->next_out=NULL;free(input);free(output);RETURN(result);
    }
    if(IS("asprintf")||IS("vasprintf")||IS("snprintf")||IS("vsnprintf")||IS("__vsnprintf_chk")){
        uint32_t format=IS("asprintf")||IS("vasprintf")?b:IS("__vsnprintf_chk")?a32_arg(r,4):c;
        a32_arguments args={.index=IS("asprintf")?2:3};
        if(IS("vasprintf")||IS("vsnprintf")||IS("__vsnprintf_chk")){
            args.memory=1;args.va=IS("vasprintf")?c:IS("vsnprintf")?d:a32_arg(r,5);
        }
        if(a32_string(r,format,x,sizeof x))return;
        int length=a32_format(r,y,sizeof y,x,args);if(length<0){a32_fail(r,"unsupported printf format");return;}
        uint32_t dest=a,size= b;
        if(IS("asprintf")||IS("vasprintf")){size=(uint32_t)length+1;dest=a32_alloc(r,size);a32_put(r,a,dest);}
        if(size){uint32_t n=(uint32_t)length<size?(uint32_t)length:size-1;uint8_t zero=0;
            if((n&&uc_mem_write(r->uc,dest,y,n))||uc_mem_write(r->uc,(uint64_t)dest+n,&zero,1))a32_fail(r,"printf output");}
        RETURN(length);
    }
    if(IS("sscanf")){if(a32_string(r,a,x,sizeof x)||a32_string(r,b,y,sizeof y))return;RETURN(a32_sscanf(r,x,y));}
    if(IS("ceilf")||IS("floorf")){float value;memcpy(&value,&a,4);value=IS("ceilf")?ceilf(value):floorf(value);memcpy(&v,&value,4);RETURN(v);}
    if(IS("strtol")||IS("strtoul")||IS("atoi")){
        if(a32_string(r,a,x,sizeof x))return;
        char *end=x;
        uint32_t value=IS("strtoul")?(uint32_t)strtoul(x,&end,(int)c):(uint32_t)strtol(x,&end,IS("atoi")?10:(int)c);
        if(!IS("atoi")&&b)a32_put(r,b,a+(uint32_t)(end-x));
        RETURN(value);
    }
    if(IS("strspn")||IS("strcspn")||IS("strpbrk")){
        if(a32_string(r,a,x,sizeof x)||a32_string(r,b,y,sizeof y))return;
        if(IS("strspn"))RETURN(strspn(x,y));
        if(IS("strcspn"))RETURN(strcspn(x,y));
        char *p=strpbrk(x,y);RETURN(p?a+(uint32_t)(p-x):0);
    }
    if(IS("malloc"))RETURN(a32_alloc(r,a));
    if(IS("realloc")){
        uint32_t old=0;for(unsigned i=0;i<r->nalloc;i++)if(r->allocations[i].address==a){old=r->allocations[i].size;break;}
        if(a&&!old){a32_fail(r,"unknown realloc pointer");return;}
        uint32_t dest=a32_alloc(r,b),n=old<b?old:b;
        if(n){uint8_t *buf=malloc(n);if(!buf){a32_fail(r,"realloc buffer");return;}
            if(uc_mem_read(r->uc,a,buf,n)||uc_mem_write(r->uc,dest,buf,n))a32_fail(r,"realloc copy");
            free(buf);}
        a32_release(r,a);RETURN(dest);
    }
    if(IS("calloc")){if((uint64_t)a*b>A32_LIMIT-A32_HEAP){a32_fail(r,"calloc overflow");return;}uint32_t p=a32_alloc(r,a*b);a32_zero(r,p,a*b);RETURN(p);}
    if(IS("free")){a32_release(r,a);RETURN(0);}
    if(IS("pthread_mutex_trylock"))RETURN(0);
    if(IS("__cxa_finalize")||IS("__cxa_atexit")||IS("pthread_atfork")||IS("pthread_mutex_lock")||IS("pthread_mutex_unlock")||IS("pthread_mutex_init")||IS("pthread_mutex_destroy")||IS("pthread_mutexattr_init")||IS("pthread_mutexattr_destroy")||IS("pthread_mutexattr_settype")||IS("cacheflush")||IS("mprotect")||IS("sigprocmask")||IS("dlclose"))RETURN(0);
    if(IS("pthread_key_create")){if(++r->nextkey>=128){a32_fail(r,"TLS keys");return;}a32_put(r,a,r->nextkey);RETURN(0);}
    if(IS("pthread_getspecific")){if(a>=128){a32_fail(r,"TLS key");return;}RETURN(r->keys[r->current+1][a]);}
    if(IS("pthread_setspecific")){if(a>=128){a32_fail(r,"TLS key");return;}r->keys[r->current+1][a]=b;RETURN(0);}
    if(IS("pthread_create"))RETURN(a32_spawn(r,a,c,d));
    if(IS("fork"))RETURN(a32_fork(r));
    if(IS("prctl")){if(a==3)RETURN(1);if(a==4||a==15||a==0x59616d61)RETURN(0);a32_fail(r,"unsupported prctl");return;}
    if(IS("ptrace"))RETURN(a32_ptrace(r,a,b,c,d));
    if(IS("waitpid")){
        if(r->trace_pending&&(a==r->trace_pid||a==UINT32_MAX)){r->trace_pending=0;if(b)a32_put(r,b,r->trace_status);RETURN(r->trace_pid);}
        if(a>=2001&&a<2001+r->nthread&&!r->threads[a-2001].active){if(b)a32_put(r,b,r->threads[a-2001].exit_status);RETURN(a);}
        if(c&1)RETURN(0);
        a32_thread *t=r->current<0?&r->main:&r->threads[r->current];t->wait_pid=a;t->wait_status=b;
        a32_return(r,0);uc_emu_stop(r->uc);return;
    }
    if(IS("exit")||IS("_exit")||IS("exit_group")){
        if(r->current>=0&&r->threads[r->current].memory){r->threads[r->current].active=0;r->threads[r->current].exit_status=(a&255)<<8;uc_emu_stop(r->uc);return;}
        a32_fail(r,"guest exited during recovery");return;
    }
    if(IS("pthread_self"))RETURN(1234+r->current+1);
    if(IS("pthread_equal"))RETURN(a==b);
    if(IS("sigaction")){
        if(!a||a>64)RETURN(-1);
        if(c){a32_put(r,c,r->handlers[a]);a32_put(r,c+4,0);a32_put(r,c+8,0);}
        if(b)r->handlers[a]=a32_get(r,b);
        RETURN(0);
    }
    if(IS("sigsetjmp")||IS("setjmp")||IS("_setjmp")){
        unsigned i;for(i=0;i<r->njump;i++)if(r->jumps[i].guest==a)break;
        if(i==r->njump){if(i==16||uc_context_alloc(r->uc,&r->jumps[i].cpu)){a32_fail(r,"jump context allocation");return;}r->jumps[i].guest=a;r->njump++;}
        a32_return(r,0);if(uc_context_save(r->uc,r->jumps[i].cpu))a32_fail(r,"jump context save");return;
    }
    if(IS("siglongjmp")||IS("longjmp")||IS("_longjmp")){
        for(unsigned i=0;i<r->njump;i++)if(r->jumps[i].guest==a){
            if(uc_context_restore(r->uc,r->jumps[i].cpu))a32_fail(r,"jump context restore");
            a32_set(r,UC_ARM_REG_R0,b?b:1);return;
        }a32_fail(r,"unknown jump buffer");return;
    }
    if(IS("sigfillset")||IS("sigemptyset")){a32_put(r,a,IS("sigfillset")?UINT32_MAX:0);RETURN(0);}
    if(IS("sigdelset")||IS("sigaddset")){if(!b||b>32)RETURN(-1);uint32_t mask=1u<<(b-1),set=a32_get(r,a);a32_put(r,a,IS("sigdelset")?set&~mask:set|mask);RETURN(0);}
    if(IS("pthread_detach"))RETURN(0);
    if(IS("sleep")||IS("usleep")||IS("sched_yield")){
        r->clock_ns+=IS("sleep")?(uint64_t)a*1000000000:IS("usleep")?(uint64_t)a*1000:1000000;
        a32_return(r,0);uc_emu_stop(r->uc);return;
    }
    if(IS("pthread_cond_init")||IS("pthread_cond_destroy"))RETURN(0);
    if(IS("pthread_cond_wait")||IS("pthread_cond_timedwait")){
        a32_thread *t=r->current<0?&r->main:&r->threads[r->current];t->condition=a;
        a32_return(r,0);uc_emu_stop(r->uc);return;
    }
    if(IS("pthread_cond_signal")||IS("pthread_cond_broadcast")){
        if(r->main.condition==a)r->main.condition=0;
        for(unsigned i=0;i<r->nthread;i++)if(r->threads[i].condition==a)r->threads[i].condition=0;
        RETURN(0);
    }
    if(IS("pthread_join")){if(!a||a>r->nthread)RETURN(3);if(r->threads[a-1].active){a32_return(r,0);uc_emu_stop(r->uc);return;}if(b)a32_put(r,b,0);RETURN(0);}
    if(IS("pipe")||IS("pipe2")||IS("socketpair")){
        if(r->nchannel==16)RETURN(-1);
        unsigned i=r->nchannel++;a32_channel *ch=&r->channels[i];
        ch->readfd=0x400+i*2;ch->writefd=ch->readfd+1;uint32_t out=IS("socketpair")?d:a;
        a32_put(r,out,ch->readfd);a32_put(r,out+4,ch->writefd);RETURN(0);
    }
    if(IS("read")||IS("write")||IS("__read_chk"))for(unsigned i=0;i<r->nchannel;i++){
        a32_channel *ch=&r->channels[i];
        if((IS("read")||IS("__read_chk"))&&a==ch->readfd){
            uint32_t n=c<ch->size?c:ch->size;
            if(!n&&c){
                a32_thread *t=r->current<0?&r->main:&r->threads[r->current];t->blocked=a;t->buffer=b;t->length=c;
                a32_return(r,0);uc_emu_stop(r->uc);return;
            }
            if(n&&uc_mem_write(r->uc,b,ch->data,n))a32_fail(r,"pipe read");
            memmove(ch->data,ch->data+n,ch->size-n);ch->size-=n;RETURN(n);
        }
        if(IS("write")&&a==ch->writefd){if(c>sizeof ch->data-ch->size)RETURN(-1);
            if(c&&uc_mem_read(r->uc,b,ch->data+ch->size,c))a32_fail(r,"pipe write");
            ch->size+=c;RETURN(c);}
    }
    if(IS("memcpy")||IS("memmove")||IS("__memcpy_chk")||IS("__memmove_chk")||IS("__aeabi_memcpy")||IS("__aeabi_memcpy4")||IS("__aeabi_memcpy8")){
        if(c>A32_MAX_IMAGE){a32_fail(r,"copy size");return;}uint8_t *buf=malloc(c?c:1);
        if(!buf){a32_fail(r,"copy allocation");return;}
        if(uc_mem_read(r->uc,b,buf,c)||uc_mem_write(r->uc,a,buf,c))a32_fail(r,"memory copy");
        free(buf);RETURN(a);
    }
    if(IS("memset")||IS("__memset_chk")||IS("__aeabi_memset")||IS("__aeabi_memclr")||IS("__aeabi_memclr4")||IS("__aeabi_memclr8")){
        if(!strncmp(name,"__aeabi_",8)){uint32_t n=b;b=strstr(name,"memclr")?0:c;c=n;}
        if(c>A32_MAX_IMAGE){a32_fail(r,"fill size");return;}uint8_t buf[4096];memset(buf,(uint8_t)b,sizeof buf);
        for(uint32_t i=0;i<c;){uint32_t n=c-i<sizeof buf?c-i:sizeof buf;if(uc_mem_write(r->uc,(uint64_t)a+i,buf,n)){a32_fail(r,"memory fill");break;}i+=n;}RETURN(a);
    }
    if(IS("memcmp")||IS("bcmp")){
        for(uint32_t i=0;i<c;i++){uint8_t l=0,h=0;if(uc_mem_read(r->uc,(uint64_t)a+i,&l,1)||uc_mem_read(r->uc,(uint64_t)b+i,&h,1)){a32_fail(r,"memory compare");return;}if(l!=h)RETURN((int)l-h);}RETURN(0);
    }
    if(IS("strlen")||IS("strcmp")||IS("strncmp")||IS("strcpy")||IS("strncpy")||IS("__strncpy_chk")||IS("__strncpy_chk2")||IS("strstr")||IS("strchr")||IS("strrchr")){
        if(a32_string(r,a,x,sizeof x))return;
        if(IS("strlen"))RETURN(strlen(x));
        if(IS("strchr")||IS("strrchr")){char *p=IS("strchr")?strchr(x,(int)b):strrchr(x,(int)b);RETURN(p?a+(uint32_t)(p-x):0);}
        if(a32_string(r,b,y,sizeof y))return;
        if(IS("strcmp"))RETURN(strcmp(x,y));
        if(IS("strncmp"))RETURN(strncmp(x,y,c));
        if(IS("strstr")){char *p=strstr(x,y);RETURN(p?a+(uint32_t)(p-x):0);}
        if(IS("strcpy")){if(uc_mem_write(r->uc,a,y,strlen(y)+1))a32_fail(r,"strcpy");RETURN(a);}
        if(c>sizeof y){a32_fail(r,"strncpy size");return;}size_t n=strlen(y);if(n<c)memset(y+n,0,c-n);
        if(uc_mem_write(r->uc,a,y,c))a32_fail(r,"strncpy");
        RETURN(a);
    }
    if(IS("getpid")||IS("gettid"))RETURN(r->current>=0&&r->threads[r->current].memory?2001+r->current:1234);
    if(IS("getppid"))RETURN(r->current>=0&&r->threads[r->current].memory?1234:1);
    if(IS("getuid")||IS("geteuid"))RETURN(10000);
    if(IS("getpagesize"))RETURN(4096);
    if(IS("getauxval")){if(a==6)RETURN(4096);if(a==16)RETURN(0x1fb8d7);RETURN(0);}
    if(IS("uname")){
        uint8_t fields[390]={0};const char *values[]={"Linux","localhost","5.10.0-android","#1 SMP PREEMPT","armv7l","localdomain"};
        for(unsigned i=0;i<6;i++)memcpy(fields+i*65,values[i],strlen(values[i]));
        if(uc_mem_write(r->uc,a,fields,sizeof fields))a32_fail(r,"uname output");
        RETURN(0);
    }
    if(IS("sysconf")){if(a==39)RETURN(4096);if(a==0x60||a==0x61)RETURN(4);a32_fail(r,"unsupported sysconf");return;}
    if(IS("__errno"))RETURN(A32_TLS+0x100);
    if(IS("getenv")||IS("dlerror"))RETURN(0);
    if(IS("getxattr")||IS("lgetxattr")||IS("fgetxattr")){a32_put(r,A32_TLS+0x100,ENODATA);RETURN(-1);}
    if(IS("arc4random_buf")){
        if(b>A32_MAX_IMAGE){a32_fail(r,"random buffer size");return;}
        for(uint32_t i=0;i<b;i++){r->random_state=r->random_state*1664525u+1013904223u;uint8_t byte=(uint8_t)(r->random_state>>24);
            if(uc_mem_write(r->uc,(uint64_t)a+i,&byte,1)){a32_fail(r,"random buffer write");return;}}RETURN(0);
    }
    if(IS("arc4random")||IS("arc4random_uniform")){r->random_state=r->random_state*1664525u+1013904223u;RETURN(IS("arc4random_uniform")?(a?r->random_state%a:0):r->random_state);}
    if(IS("strerror"))RETURN(a32_cstr(r,strerror((int)a)));
    if(IS("newlocale"))RETURN(a32_alloc(r,16));
    if(IS("uselocale")){uint32_t old=r->locale;if(a)r->locale=a;RETURN(old?old:UINT32_MAX);}
    if(IS("freelocale"))RETURN(0);
    if(IS("mbtowc")||IS("mbrtowc")){
        if(!b)RETURN(0);
        if(!c)RETURN(IS("mbrtowc")?-2:-1);
        uint8_t bytes[4]={0};if(uc_mem_read(r->uc,b,bytes,1)){a32_fail(r,"multibyte read");return;}
        unsigned count=bytes[0]<0x80?1:(bytes[0]&0xe0)==0xc0?2:(bytes[0]&0xf0)==0xe0?3:(bytes[0]&0xf8)==0xf0?4:0;
        if(!count||count>c)RETURN(IS("mbrtowc")?-2:-1);
        if(uc_mem_read(r->uc,b,bytes,count)){a32_fail(r,"multibyte read");return;}
        uint32_t code=count==1?bytes[0]:bytes[0]&((1u<<(7-count))-1);
        for(unsigned i=1;i<count;i++){if((bytes[i]&0xc0)!=0x80)RETURN(-1);code=(code<<6)|(bytes[i]&63);}
        if(code>0x10ffff||(code>=0xd800&&code<=0xdfff)||(count==2&&code<0x80)||(count==3&&code<0x800)||(count==4&&code<0x10000))RETURN(-1);
        if(a)a32_put(r,a,code);
        RETURN(code?count:0);
    }
    if(IS("__ctype_get_mb_cur_max"))RETURN(4);
    if(IS("btowc"))RETURN(a<=127?a:UINT32_MAX);
    if(IS("dlopen")||IS("android_dlopen_ext"))RETURN(0x18010000);
    if(IS("dl_unwind_find_exidx")){
        for(unsigned k=0;k<2;k++){a32_image *m=k?&r->game:&r->shield;int contains=0;
            for(unsigned i=0;i<m->nseg;i++)if(a>=m->bias+m->seg[i].va&&a-(m->bias+m->seg[i].va)<m->seg[i].memsz)contains=1;
            if(!contains)continue;
            uint32_t off=a32_u32(m->raw+28);unsigned count=a32_u16(m->raw+44);
            for(unsigned i=0;i<count;i++){const uint8_t *ph=m->raw+off+i*32;
                if(a32_u32(ph)==0x70000001){a32_put(r,b,a32_u32(ph+16)/8);RETURN(m->bias+a32_u32(ph+8));}
            }
        }a32_put(r,b,0);RETURN(0);
    }
    if(IS("dlsym")){if(a32_string(r,b,x,sizeof x))return;v=a32_export(&r->shield,x);if(!v)v=a32_export(&r->game,x);RETURN(v?v:a32_stub(r,x));}
    if(IS("time")){if(a)a32_put(r,a,1700000000);RETURN(1700000000);}
    if(IS("mktime")||IS("timegm")){
        struct tm tm={0};int values[9];for(unsigned i=0;i<9;i++)values[i]=(int32_t)a32_get(r,a+i*4);
        tm.tm_sec=values[0];tm.tm_min=values[1];tm.tm_hour=values[2];tm.tm_mday=values[3];tm.tm_mon=values[4];tm.tm_year=values[5];tm.tm_isdst=0;
        time_t result=timegm(&tm);a32_put(r,a+24,(uint32_t)tm.tm_wday);a32_put(r,a+28,(uint32_t)tm.tm_yday);a32_put(r,a+32,0);RETURN(result);
    }
    if(IS("gettimeofday")){a32_put(r,a,1700000000);a32_put(r,a+4,0);RETURN(0);}
    if(IS("clock_gettime")){r->clock_ns+=1000000;a32_put(r,b,(a==0?1700000000:1000)+(uint32_t)(r->clock_ns/1000000000));a32_put(r,b+4,(uint32_t)(r->clock_ns%1000000000));RETURN(0);}
    if(IS("open")||IS("openat")||IS("open64")||IS("__open_2")||IS("fopen")||IS("fopen64")){
        v=a32_open(r,IS("openat")?b:a);if(v==UINT32_MAX){a32_put(r,A32_TLS+0x100,ENOENT);RETURN(IS("fopen")||IS("fopen64")?0:UINT32_MAX);}RETURN(v);
    }
    if(IS("access")||IS("__access")){
        uint32_t fd=a32_open(r,a);a32_file *f=a32_file_at(r,fd);if(f){f->used=0;RETURN(0);}
        a32_put(r,A32_TLS+0x100,ENOENT);RETURN(-1);
    }
    if(IS("readlink")){
        if(a32_string(r,a,x,sizeof x))return;
        const char *target=NULL;
        if(!strcmp(x,"/proc/self/exe"))target="/system/bin/app_process32";
        const char *fd=strstr(x,"/fd/");if(fd){unsigned index=(unsigned)strtoul(fd+4,NULL,10);if(a32_file_at(r,index))target=r->file_paths[index-0x200];}
        if(!target){a32_put(r,A32_TLS+0x100,ENOENT);RETURN(-1);}
        size_t n=strlen(target);if(n>c)n=c;if(n&&uc_mem_write(r->uc,b,target,n))a32_fail(r,"readlink output");RETURN(n);
    }
    if(IS("close")||IS("fclose")){
        if(a>=0x400&&a<0x400+r->nchannel*2)RETURN(0);
        if(a>=0x700&&a<0x700+r->nsocket)RETURN(0);
        a32_file *f=a32_file_at(r,a);if(!f){a32_put(r,A32_TLS+0x100,EBADF);RETURN(-1);}f->used=0;RETURN(0);
    }
    if(IS("read")||IS("__read_chk"))RETURN(a32_read(r,a32_file_at(r,a),b,c));
    if(IS("pread")||IS("pread64")){
        a32_file *f=a32_file_at(r,a);if(!f)RETURN(-1);size_t saved=f->pos;
        uint64_t offset=IS("pread64")?(uint64_t)a32_arg(r,4)|((uint64_t)a32_arg(r,5)<<32):d;
        if(offset>f->size)RETURN(-1);
        f->pos=(size_t)offset;v=a32_read(r,f,b,c);f->pos=saved;RETURN(v);
    }
    if(IS("fread")){if(!b||!c)RETURN(0);if((uint64_t)b*c>UINT32_MAX)RETURN(0);v=a32_read(r,a32_file_at(r,d),a,b*c);RETURN(v==UINT32_MAX?0:v/b);}
    if(IS("fgets")){a32_file *f=a32_file_at(r,c);if(!f||b<2||f->pos==f->size)RETURN(0);uint32_t n=0;
        while(n<b-1&&f->pos<f->size){uint8_t ch=f->data[f->pos++];if(uc_mem_write(r->uc,a+n,&ch,1)){a32_fail(r,"fgets");return;}n++;if(ch=='\n')break;}
        uint8_t z=0;if(uc_mem_write(r->uc,a+n,&z,1))a32_fail(r,"fgets terminator");RETURN(a);}
    if(IS("fseek")||IS("lseek")){a32_file *f=a32_file_at(r,a);if(!f)RETURN(-1);int64_t base=c==0?0:c==1?(int64_t)f->pos:c==2?(int64_t)f->size:-1,pos=base+(int32_t)b;
        if(base<0||pos<0||(uint64_t)pos>f->size)RETURN(-1);
        f->pos=(size_t)pos;RETURN(IS("fseek")?0:pos);}
    if(IS("ftell")){a32_file *f=a32_file_at(r,a);RETURN(f?f->pos:UINT32_MAX);}
    if(IS("feof")){a32_file *f=a32_file_at(r,a);RETURN(f&&f->pos==f->size);}
    if(IS("ferror"))RETURN(0);
    if(IS("fileno"))RETURN(a);
    if(IS("stat64")||IS("lstat64")||IS("fstat64")||IS("stat")||IS("fstat")){
        a32_file *f=NULL;uint32_t fd=a;
        if(!IS("fstat64")&&!IS("fstat")){fd=a32_open(r,a);f=a32_file_at(r,fd);}else f=a32_file_at(r,a);
        if(!f){a32_put(r,A32_TLS+0x100,ENOENT);RETURN(-1);}
        uint8_t statbuf[104]={0};a32_p32(statbuf,1);a32_p32(statbuf+12,12345);
        a32_p32(statbuf+16,0100644);a32_p32(statbuf+20,1);a32_p32(statbuf+24,10000);a32_p32(statbuf+28,10000);
        a32_p32(statbuf+48,(uint32_t)f->size);a32_p32(statbuf+56,4096);a32_p32(statbuf+64,(uint32_t)((f->size+511)/512));
        a32_p32(statbuf+72,1700000000);a32_p32(statbuf+80,1700000000);a32_p32(statbuf+88,1700000000);a32_p32(statbuf+96,12345);
        if(uc_mem_write(r->uc,b,statbuf,sizeof statbuf))a32_fail(r,"stat output");
        if(!IS("fstat64")&&!IS("fstat"))f->used=0;
        RETURN(0);
    }
    if(IS("__system_property_get")){if(a32_string(r,a,x,sizeof x))return;
        static const char *properties[][2]={{"ro.build.version.sdk","30"},{"ro.product.cpu.abi","armeabi-v7a"},
            {"ro.kernel.version","4.14.190"},{"ro.product.manufacturer","Google"},{"ro.product.model","Pixel 5"},
            {"ro.product.device","redfin"},{"ro.build.fingerprint","google/redfin/redfin:11/RQ3A.211001.001/7641976:user/release-keys"},
            {"ro.build.tags","release-keys"},{"ro.build.type","user"},{"ro.debuggable","0"},{"ro.secure","1"}};
        const char *value="";for(unsigned i=0;i<sizeof properties/sizeof properties[0];i++)if(!strcmp(x,properties[i][0])){value=properties[i][1];break;}
        if(uc_mem_write(r->uc,b,value,strlen(value)+1))a32_fail(r,"property");
        RETURN(strlen(value));}
    if(IS("jvm_GetEnv")||IS("jvm_AttachCurrentThread")){a32_put(r,b,A32_ENV);RETURN(0);}
    if(IS("jvm_DetachCurrentThread"))RETURN(0);
    if(!strncmp(name,"jni_",4)){
        unsigned slot=(unsigned)strtoul(name+4,NULL,10);
        if(slot==4)RETURN(0x10006);
        if(slot==15||slot==17||slot==22||slot==23||slot==170||slot==228)RETURN(0);
        if(slot==21||slot==25||slot==169)RETURN(b);
        if(slot==31)RETURN(a32_cstr(r,"java/lang/Class"));
        if(slot==28||slot==29||slot==30){
            if(a32_string(r,b,x,sizeof x))return;
            if(!strcmp(x,"java/io/File"))RETURN(slot==28?d:a32_get(r,d));
            fprintf(stderr,"error: unsupported ARM32 Java constructor %s\n",x);
        }
        if(slot==6||slot==167||slot==33||slot==94||slot==113||slot==144){
            if(a32_string(r,slot==6||slot==167?b:c,x,sizeof x))return;
            RETURN(a32_cstr(r,x));
        }
        if(slot==141||slot==142||slot==143){
            if(a32_string(r,b,x,sizeof x)||a32_string(r,c,y,sizeof y))return;
            if(!strcmp(x,"android/os/Process")&&!strcmp(y,"setArgV0"))RETURN(0);
            if(r->verbose){char message[8192];uint32_t argument=slot==141?d:a32_get(r,d);if(argument&&!a32_string(r,argument,message,sizeof message))fprintf(stderr,"    [arm32 Java argument] %s\n",message);}
            fprintf(stderr,"error: unsupported ARM32 Java call %s.%s\n",x,y);a32_fail(r,"Java static-void call");return;
        }
        if(slot==168){if(a32_string(r,b,x,sizeof x))return;RETURN(strlen(x));}
        if(slot>=154&&slot<=162){
            unsigned i;for(i=0;i<r->nfield;i++)if(r->fields[i].id==c)break;
            if(i==r->nfield){if(i==256){a32_fail(r,"JNI field limit");return;}r->fields[i].id=c;r->nfield++;}
            r->fields[i].value=slot==160||slot==162?(uint64_t)a32_arg(r,4)|((uint64_t)a32_arg(r,5)<<32):d;RETURN(0);
        }
        if(slot>=145&&slot<=153)for(unsigned i=0;i<r->nfield;i++)if(r->fields[i].id==c){
            if(slot==151||slot==153)a32_set(r,UC_ARM_REG_R1,(uint32_t)(r->fields[i].value>>32));
            RETURN(r->fields[i].value);
        }
        if(slot==37||slot==38||slot==39){
            if(a32_string(r,c,x,sizeof x)||a32_string(r,b,y,sizeof y))return;
            if(!strcmp(x,"exists"))RETURN(!strcmp(y,"/data/app/lib/arm")||!strcmp(y,"/data/app/base.apk"));
            if(!strcmp(x,"hasSystemFeature")&&!strcmp(y,"android/app/ApplicationPackageManager")){
                if(a32_string(r,slot==37?d:a32_get(r,d),x,sizeof x))return;
                if(!strncmp(x,"org.chromium.",13))RETURN(0);
            }
            fprintf(stderr,"error: unsupported ARM32 Java boolean call %s.%s\n",y,x);
        }
        if(slot==117||slot==118||slot==119){
            if(a32_string(r,b,x,sizeof x)||a32_string(r,c,y,sizeof y))return;
            if(!strcmp(x,"android/os/Debug")&&(!strcmp(y,"isDebuggerConnected")||!strcmp(y,"waitingForDebugger")))RETURN(0);
        }
        if(slot==95||slot==145){if(a32_string(r,c,x,sizeof x))return;const char *value=NULL;
            if(!strcmp(x,"sourceDir"))value="/data/app/base.apk";
            if(!strcmp(x,"nativeLibraryDir"))value="/data/app/lib/arm";
            if(!strcmp(x,"dataDir"))value="/data/user/0";
            if(!strcmp(x,"primaryCpuAbi"))value="armeabi-v7a";
            if(!strcmp(x,"packageName"))value=r->metadata.package;
            if(!strcmp(x,"versionName"))value=r->metadata.version;
            if(!strcmp(x,"splitSourceDirs")||!strcmp(x,"splitPublicSourceDirs"))RETURN(0);
            if(value)RETURN(a32_cstr(r,value));
            fprintf(stderr,"error: unsupported ARM32 Java field %s\n",x);
        }
        if(slot==150){if(a32_string(r,c,x,sizeof x))return;if(!strcmp(x,"SDK_INT"))RETURN(30);if(!strcmp(x,"versionCode"))RETURN(strtoul(r->metadata.version,NULL,10));}
        if(slot==34||slot==35||slot==36||slot==114||slot==115||slot==116){
            if(a32_string(r,c,x,sizeof x))return;
            const char *value=NULL;
            if(!strcmp(x,"currentActivityThread"))value="android/app/ActivityThread";
            if(!strcmp(x,"getSystemContext")||!strcmp(x,"getApplication"))value="android/app/ContextImpl";
            if(!strcmp(x,"getPackageName"))value=r->metadata.package;
            if(!strcmp(x,"getPackageManager"))value="android/app/ApplicationPackageManager";
            if(!strcmp(x,"getApplicationInfo"))value="android/content/pm/ApplicationInfo";
            if(!strcmp(x,"getPackageInfo"))value="android/content/pm/PackageInfo";
            if(!strcmp(x,"getClassLoader"))value="java/lang/ClassLoader";
            if(!strcmp(x,"getAbsolutePath")||!strcmp(x,"getPath")||!strcmp(x,"toString"))RETURN(b);
            if(!strcmp(x,"listFiles")){
                uint32_t array=a32_alloc(r,12);a32_put(r,array,2);
                char path[1024];snprintf(path,sizeof path,"/data/app/lib/arm/%s",r->shield.name);a32_put(r,array+4,a32_cstr(r,path));
                snprintf(path,sizeof path,"/data/app/lib/arm/%s",r->game.name);a32_put(r,array+8,a32_cstr(r,path));RETURN(array);
            }
            if(!strcmp(x,"getName")){
                if(a32_string(r,b,y,sizeof y))return;
                const char *last=strrchr(y,'/');RETURN(a32_cstr(r,last?last+1:y));
            }
            if(value)RETURN(a32_cstr(r,value));
            fprintf(stderr,"error: unsupported ARM32 Java object call %s\n",x);
        }
        if(slot==171)RETURN(a32_get(r,b));
        if(slot==173){uint32_t count=a32_get(r,b);if(c>=count){a32_fail(r,"JNI array bounds");return;}RETURN(a32_get(r,b+4+c*4));}
        if(slot==215){
            if(d>256-r->nnative){a32_fail(r,"JNI native count");return;}
            for(unsigned i=0;i<d;i++){
                unsigned j=r->nnative++;uint32_t method=a32_get(r,c+i*12),signature=a32_get(r,c+i*12+4),function=a32_get(r,c+i*12+8);
                if(a32_string(r,method,x,sizeof x)||a32_string(r,signature,y,sizeof y))return;
                r->natives[j].owner=b;r->natives[j].name=a32_cstr(r,x);r->natives[j].signature=a32_cstr(r,y);r->natives[j].function=function;
            }RETURN(0);
        }
        fprintf(stderr,"error: unsupported ARM32 JNI slot %u\n",slot);a32_fail(r,"JNI call");return;
    }
    fprintf(stderr,"error: unsupported ARM32 import %s\n",name);a32_fail(r,"import");
#undef IS
#undef RETURN
}
static void a32_interrupt(uc_engine *uc,uint32_t number,void *user){
    a32_runtime *r=user;(void)uc;
    uint32_t nr=a32_reg(r,UC_ARM_REG_R7),v;
    if(number!=2){
        if(r->trace_pid&&r->current<0){r->trace_status=((number==1?4u:5u)<<8)|0x7f;r->trace_pending=r->trace_stopped=1;uc_emu_stop(r->uc);return;}
        unsigned signal=number==1?4:5;
        if(r->handlers[signal]>1){a32_set(r,UC_ARM_REG_R0,signal);a32_set(r,UC_ARM_REG_R1,0);a32_set(r,UC_ARM_REG_R2,0);a32_set(r,UC_ARM_REG_PC,r->handlers[signal]);return;}
        a32_fail(r,"unexpected interrupt");return;
    }
    static const struct {uint32_t number;const char *name;} imports[]={
        {1,"exit"},{248,"exit"},{3,"read"},{217,"read"},{4,"write"},
        {5,"open"},{6,"close"},{19,"lseek"},{20,"getpid"},{224,"getpid"},
        {64,"getppid"},{26,"ptrace"},{33,"access"},{42,"pipe"},{172,"prctl"},
        {359,"pipe2"},{263,"clock_gettime"},{195,"stat64"},{196,"lstat64"},
        {197,"fstat64"},{85,"readlink"},{322,"openat"}
    };
    for(unsigned i=0;i<sizeof imports/sizeof imports[0];i++)if(nr==imports[i].number){
        uint32_t pc=a32_reg(r,UC_ARM_REG_PC)|((a32_reg(r,UC_ARM_REG_CPSR)&32)?1u:0u);
        a32_import(r->uc,a32_stub(r,imports[i].name),4,r);
        if(a32_reg(r,UC_ARM_REG_R0)==UINT32_MAX){uint32_t error=a32_get(r,A32_TLS+0x100);if(error&&error<4096)a32_set(r,UC_ARM_REG_R0,0u-error);}
        a32_set(r,UC_ARM_REG_PC,pc);return;
    }
    if(nr==180){ /* pread64 has an aligned 64-bit offset in r4/r5. */
        a32_file *f=a32_file_at(r,a32_reg(r,UC_ARM_REG_R0));
        uint64_t offset=(uint64_t)a32_reg(r,UC_ARM_REG_R4)|((uint64_t)a32_reg(r,UC_ARM_REG_R5)<<32);
        if(!f||offset>f->size)v=(uint32_t)-9;
        else {size_t saved=f->pos;f->pos=(size_t)offset;v=a32_read(r,f,a32_reg(r,UC_ARM_REG_R1),a32_reg(r,UC_ARM_REG_R2));f->pos=saved;}
        a32_set(r,UC_ARM_REG_R0,v);return;
    }
    if(nr==140){
        a32_file *f=a32_file_at(r,a32_reg(r,UC_ARM_REG_R0));uint32_t whence=a32_reg(r,UC_ARM_REG_R4);
        int64_t delta=(int64_t)(((uint64_t)a32_reg(r,UC_ARM_REG_R1)<<32)|a32_reg(r,UC_ARM_REG_R2));
        int64_t base=!f?-1:whence==0?0:whence==1?(int64_t)f->pos:whence==2?(int64_t)f->size:-1;
        if(base<0||delta < -base||delta>(int64_t)UINT32_MAX-base){a32_set(r,UC_ARM_REG_R0,(uint32_t)-22);return;}
        f->pos=(size_t)(base+delta);uint32_t result=a32_reg(r,UC_ARM_REG_R3);
        a32_put(r,result,(uint32_t)f->pos);a32_put(r,result+4,0);a32_set(r,UC_ARM_REG_R0,0);return;
    }
    if(nr==192){
        v=a32_mmap(r,a32_reg(r,UC_ARM_REG_R0),a32_reg(r,UC_ARM_REG_R1),a32_reg(r,UC_ARM_REG_R3),a32_reg(r,UC_ARM_REG_R4),(uint64_t)a32_reg(r,UC_ARM_REG_R5)*4096);
        a32_set(r,UC_ARM_REG_R0,v);return;
    }
    if(nr==91){uint32_t address=a32_reg(r,UC_ARM_REG_R0),length=a32_reg(r,UC_ARM_REG_R1);
        a32_set(r,UC_ARM_REG_R0,!length||length>UINT32_MAX-4095||uc_mem_unmap(r->uc,address,(length+4095)&~4095u)?(uint32_t)-22:0);return;}
    switch(nr){
    case 55:case 221:{uint32_t command=a32_reg(r,UC_ARM_REG_R1);if(command>=1&&command<=4)v=0;else v=(uint32_t)-22;break;}
    case 281: if(r->nsocket==64){v=(uint32_t)-24;break;}v=0x700+r->nsocket++;break;
    case 283:v=(uint32_t)-111;break; /* offline connect: ECONNREFUSED */
    case 24:case 49:case 199:case 201:v=10000;break;
    case 37:case 67:case 125:case 126:case 174:case 175:case 0xf0002:v=0;break;
    default:fprintf(stderr,"error: unsupported ARM EABI syscall %u\n",nr);a32_fail(r,"syscall");return;
    }a32_set(r,UC_ARM_REG_R0,v);
}
static uint32_t a32_pc(a32_runtime *r){return a32_reg(r,UC_ARM_REG_PC)|((a32_reg(r,UC_ARM_REG_CPSR)&32)?1u:0u);}
static bool a32_fault(uc_engine *uc,uc_mem_type type,uint64_t address,int size,int64_t value,void *user){
    a32_runtime *r=user;(void)value;(void)uc;
    fprintf(stderr,"error: ARM32 memory fault type=%d address=0x%llx size=%d pc=%x\n",type,(unsigned long long)address,size,a32_pc(r));
    if(r->verbose){uint8_t code[16]={0};uc_mem_read(r->uc,a32_pc(r)&~1u,code,sizeof code);
        fprintf(stderr,"    instructions:");for(unsigned i=0;i<16;i++)fprintf(stderr," %02x",code[i]);fputc('\n',stderr);
        for(unsigned i=0;i<13;i++)fprintf(stderr," r%u=%x",i,a32_reg(r,UC_ARM_REG_R0+(int)i));
        fputc('\n',stderr);
        uint8_t before[128];uint32_t start=(a32_pc(r)&~1u)-sizeof before;
        if(!uc_mem_read(r->uc,start,before,sizeof before)){
            fprintf(stderr,"    preceding %x: ",start);for(unsigned i=0;i<sizeof before;i++)fprintf(stderr,"%02x",before[i]);fputc('\n',stderr);
        }
        start=(a32_reg(r,UC_ARM_REG_LR)&~1u)-sizeof before;
        if(!uc_mem_read(r->uc,start,before,sizeof before)){
            fprintf(stderr,"    caller %x: ",start);for(unsigned i=0;i<sizeof before;i++)fprintf(stderr,"%02x",before[i]);fputc('\n',stderr);
        }
    }return false;
}
static int a32_wait_ready(a32_runtime *r,a32_thread *t){
    uint32_t pid=t->wait_pid,status=0;if(!pid)return 1;
    if(r->trace_pending&&(pid==r->trace_pid||pid==UINT32_MAX)){pid=r->trace_pid;status=r->trace_status;r->trace_pending=0;}
    else if(pid>=2001&&pid<2001+r->nthread&&!r->threads[pid-2001].active)status=r->threads[pid-2001].exit_status;
    else return 0;
    if(t->wait_status)a32_put(r,t->wait_status,status);
    a32_set(r,UC_ARM_REG_R0,pid);t->wait_pid=0;return 1;
}
static void a32_workers(a32_runtime *r){
    if(!r->nthread)return;
    uc_context *saved=NULL;if(uc_context_alloc(r->uc,&saved)||uc_context_save(r->uc,saved)){a32_fail(r,"scheduler context");if(saved)uc_context_free(saved);return;}
    for(unsigned i=0;i<r->nthread&&!r->failed;i++){
        a32_thread *t=&r->threads[i];if(!t->active||t->condition)continue;
        a32_memory *parent=NULL;unsigned parent_count=0;
        if(t->memory){
            parent=a32_snapshot(r,&parent_count);if(!parent){a32_fail(r,"parent snapshot");break;}
            r->trace_memory=parent;r->trace_count=parent_count;r->trace_cpu=saved;a32_restore(r,t->memory,t->nmemory);
        }
        if(uc_context_restore(r->uc,t->cpu)){a32_fail(r,"worker context restore");break;}
        r->current=(int)i;
        if(!a32_wait_ready(r,t))goto worker_done;
        if(t->blocked){
            for(unsigned j=0;j<r->nchannel;j++){a32_channel *ch=&r->channels[j];if(ch->readfd!=t->blocked||!ch->size)continue;
                uint32_t n=t->length<ch->size?t->length:ch->size;
                if(uc_mem_write(r->uc,t->buffer,ch->data,n)){a32_fail(r,"worker pipe read");break;}
                memmove(ch->data,ch->data+n,ch->size-n);ch->size-=n;t->blocked=0;a32_set(r,UC_ARM_REG_R0,n);break;
            }
            if(t->blocked)goto worker_done;
        }
        uc_err err=uc_emu_start(r->uc,a32_pc(r),A32_THREAD_STOP,0,1000000);
        if((a32_pc(r)&~1u)==A32_THREAD_STOP)t->active=0;
        else if(err){fprintf(stderr,"error: ARM32 worker %u: %s at %x\n",i,uc_strerror(err),a32_pc(r));a32_fail(r,"worker execution");}
worker_done:
        if(uc_context_save(r->uc,t->cpu))a32_fail(r,"worker context save");
        if(t->memory){
            a32_memory_free(t->memory,t->nmemory);t->memory=a32_snapshot(r,&t->nmemory);
            if(!t->memory)a32_fail(r,"child snapshot");
            a32_restore(r,parent,parent_count);a32_memory_free(parent,parent_count);
            r->trace_memory=NULL;r->trace_count=0;r->trace_cpu=NULL;
        }
    }
    r->current=-1;if(uc_context_restore(r->uc,saved))a32_fail(r,"scheduler restore");uc_context_free(saved);
}
static int a32_call4(a32_runtime *r,uint32_t entry,uint32_t a,uint32_t b,uint32_t c,uint32_t d){
    if(!entry)return -1;
    for(unsigned i=0;i<13;i++)a32_set(r,UC_ARM_REG_R0+(int)i,0);
    a32_set(r,UC_ARM_REG_SP,A32_SP);a32_set(r,UC_ARM_REG_LR,A32_STOP);
    a32_set(r,UC_ARM_REG_R0,a);a32_set(r,UC_ARM_REG_R1,b);a32_set(r,UC_ARM_REG_R2,c);
    a32_set(r,UC_ARM_REG_R3,d);
    uint32_t pc=entry;
    for(unsigned chunk=0;chunk<1500&&!r->failed;chunk++){
        uc_err err=uc_emu_start(r->uc,pc,A32_STOP,0,2000000);pc=a32_pc(r);
        if((pc&~1u)==A32_STOP&&!r->failed)return 0;
        if(err){
            if(r->trace_pid&&(err==UC_ERR_INSN_INVALID||err==UC_ERR_EXCEPTION)){
                r->trace_status=(4u<<8)|0x7f;r->trace_pending=r->trace_stopped=1;
            }else {fprintf(stderr,"error: ARM32 execution at 0x%x: %s\n",pc,uc_strerror(err));return -1;}
        }
        for(unsigned round=0;round<64&&!r->failed;round++){
            if(!r->main.blocked&&!r->main.condition&&!r->main.wait_pid&&!r->trace_stopped)break;
            a32_workers(r);
            a32_wait_ready(r,&r->main);
            if(r->main.blocked)for(unsigned j=0;j<r->nchannel;j++){
                a32_channel *ch=&r->channels[j];if(ch->readfd!=r->main.blocked||!ch->size)continue;
                uint32_t n=r->main.length<ch->size?r->main.length:ch->size;
                if(uc_mem_write(r->uc,r->main.buffer,ch->data,n))a32_fail(r,"main pipe read");
                memmove(ch->data,ch->data+n,ch->size-n);ch->size-=n;r->main.blocked=0;a32_set(r,UC_ARM_REG_R0,n);break;
            }
            if(!r->main.blocked&&!r->main.condition&&!r->main.wait_pid&&!r->trace_stopped)break;
        }
        if(r->main.blocked||r->main.condition||r->main.wait_pid||r->trace_stopped){a32_fail(r,"scheduler deadlock");return -1;}
        pc=a32_pc(r);
        if(r->verbose)fprintf(stderr,"    [arm32] chunk=%u pc=%x\n",chunk,pc);
    }a32_fail(r,"instruction budget");return -1;
}
static int a32_call(a32_runtime *r,uint32_t entry,uint32_t a,uint32_t b,uint32_t c){return a32_call4(r,entry,a,b,c,0);}
static int a32_initialize(a32_runtime *r){
    if(uc_open(UC_ARCH_ARM,UC_MODE_ARM,&r->uc))return -1;
    const uint32_t ranges[][2]={{0x18000000,0x1000000},{A32_STUB,0x1000000},{A32_STOP&~4095u,4096},{A32_TLS,0x10000},{0x40000000,0x1000000},{0x50000000,0x10000000}};
    for(unsigned i=0;i<sizeof ranges/sizeof ranges[0];i++)if(uc_mem_map(r->uc,ranges[i][0],ranges[i][1],UC_PROT_ALL))return -1;
    r->heap=A32_HEAP;r->current=-1;r->mmap_next=0x60000000;
    for(unsigned i=0;i<sizeof r->random;i++)r->random[i]=(uint8_t)(i*17+3);
    const char *entries[]={".","..","1234"};unsigned directory_offset=0;
    for(unsigned i=0;i<3;i++){
        uint8_t *entry=r->directory+directory_offset;uint32_t length=i==2?32:24;
        a32_p32(entry,i+1);a32_p32(entry+8,directory_offset+length);entry[16]=(uint8_t)length;entry[18]=4;
        strcpy((char *)entry+19,entries[i]);directory_offset+=length;
    }
    if(uc_mem_map(r->uc,0x42000000,0x1000000,UC_PROT_ALL))return -1;
    a32_set(r,UC_ARM_REG_C1_C0_2,0xf00000);a32_set(r,UC_ARM_REG_FPEXC,0x40000000);
    a32_set(r,UC_ARM_REG_C13_C0_3,A32_TLS);a32_put(r,A32_TLS+0x14,0x12345678);
    if(a32_map(r,&r->shield)||a32_map(r,&r->game)||a32_relocate(r,&r->shield)||a32_relocate(r,&r->game)||a32_libc(r))return -1;
    a32_put(r,A32_VM,A32_JVM);a32_put(r,A32_ENV,A32_JNI);
    for(unsigned i=0;i<234;i++){char name[32];snprintf(name,sizeof name,"jni_%u",i);a32_put(r,A32_JNI+i*4,a32_stub(r,name));}
    a32_put(r,A32_JVM+4*4,a32_stub(r,"jvm_AttachCurrentThread"));
    a32_put(r,A32_JVM+5*4,a32_stub(r,"jvm_DetachCurrentThread"));
    a32_put(r,A32_JVM+6*4,a32_stub(r,"jvm_GetEnv"));
    uc_hook imports,stop,intr,fault;
    if(uc_hook_add(r->uc,&imports,UC_HOOK_CODE,a32_import,r,A32_STUB,A32_STUB+0x1000000-1)||
       uc_hook_add(r->uc,&stop,UC_HOOK_CODE,a32_import,r,A32_STOP,A32_STOP+4095)||
       uc_hook_add(r->uc,&intr,UC_HOOK_INTR,a32_interrupt,r,1,0)||
       uc_hook_add(r->uc,&fault,UC_HOOK_MEM_INVALID,a32_fault,r,1,0))return -1;
    return r->failed?-1:0;
}
static int a32_constructors(a32_runtime *r,a32_image *m){
    if(m->tags[12]&&a32_call(r,m->bias+m->tags[12],0,0,0))return -1;
    if(m->tags[27]%4||m->tags[27]>4096)return -1;
    for(uint32_t i=0;i<m->tags[27];i+=4){
        uint32_t entry=a32_get(r,m->bias+m->tags[25]+i);
        if(entry&&entry!=UINT32_MAX&&a32_call(r,entry,0,0,0))return -1;
    }return r->failed?-1:0;
}
typedef struct {uint32_t site,file;int thumb;uint32_t entry,condition;} a32_callsite;
static int64_t a32_sign(uint32_t value,unsigned bits){return value&(1u<<(bits-1))?(int64_t)value-(1LL<<bits):value;}
static uint32_t a32_arm_call(uint32_t instruction,uint32_t site){
    if((instruction&0xfe000000u)==0xfa000000u){
        uint32_t immediate=((instruction&0xffffffu)<<2)|((instruction>>23)&2);
        return (site+8+(uint32_t)a32_sign(immediate,26))|1u;
    }
    if((instruction&0x0f000000u)!=0x0b000000u||(instruction>>28)==15)return UINT32_MAX;
    return site+8+(uint32_t)(a32_sign(instruction&0xffffff,24)*4);
}
static uint32_t a32_thumb_call(const uint8_t *p,uint32_t site,int *exchange){
    uint16_t hi=a32_u16(p),lo=a32_u16(p+2);
    if((hi&0xf800)!=0xf000)return UINT32_MAX;
    if((lo&0xd000)==0xd000)*exchange=0;
    else if((lo&0xd001)==0xc000)*exchange=1;
    else return UINT32_MAX;
    uint32_t s=(hi>>10)&1,i1=1^((lo>>13)&1)^s,i2=1^((lo>>11)&1)^s;
    uint32_t immediate=(s<<24)|(i1<<23)|(i2<<22)|((hi&1023)<<12)|((lo&2047)<<1);
    uint32_t base=*exchange?(site+4)&~3u:site+4;
    return (base+(uint32_t)a32_sign(immediate,25))|(*exchange?0:1);
}
static int a32_find_resolver(const a32_image *m,const uint8_t *image,uint32_t *resolver,a32_callsite **sites,unsigned *count){
    unsigned primary=0;for(unsigned i=1;i<m->nseg;i++)if((m->seg[i].flags&1)&&m->seg[i].filesz>m->seg[primary].filesz)primary=i;
    uint64_t limit=0;for(unsigned i=0;i<m->nseg;i++)if((uint64_t)m->seg[i].va+m->seg[i].filesz>limit)limit=(uint64_t)m->seg[i].va+m->seg[i].filesz;
    if(limit>A32_MAX_IMAGE)return -1;
    uint32_t *frequencies=calloc((size_t)(limit/4+1),sizeof *frequencies);if(!frequencies)return -1;
    for(unsigned i=0;i<m->nseg;i++){const a32_segment *s=&m->seg[i];if(!(s->flags&1))continue;
        for(uint32_t j=0;j+4<=s->filesz;j+=2){uint32_t target=UINT32_MAX;int exchange=0;
            if(!((s->va+j)&3))target=a32_arm_call(a32_u32(image+s->off+j),s->va+j);
            if(target==UINT32_MAX)target=a32_thumb_call(image+s->off+j,s->va+j,&exchange);
            if(target<limit&&!(target&3))frequencies[target/4]++;
        }
    }
    unsigned candidates=0;uint32_t entry=0;
    for(unsigned i=0;i<m->nseg;i++){const a32_segment *s=&m->seg[i];if(i==primary||!(s->flags&1))continue;
        for(uint32_t j=0;j+4<=s->filesz;j+=4){uint32_t va=s->va+j,word=a32_u32(image+s->off+j);
            if(frequencies[va/4]<4)continue;
            if((word&0xff000000u)!=0xea000000u&&
               !(j+16<=s->filesz&&word==0xe24dd004u&&a32_u32(image+s->off+j+4)==0xe92d5007u&&
                 a32_u32(image+s->off+j+8)==0xe10f2000u&&a32_u32(image+s->off+j+12)==0xe28d0014u))continue;
            /* Supported wrapper saves every integer argument and both ARM
             * argument/callee-saved registers. Do not mistake a hot PLT stub
             * or normal game function for a protector resolver. */
            int save=0;uint32_t end=j+256<s->filesz?j+256:s->filesz;
            for(uint32_t k=j;k+8<=end;k+=4)if(a32_u32(image+s->off+k)==0xe92d5fffu&&
                (a32_u32(image+s->off+k+4)&0xffbf0f00u)==0xed2d0b00u)save=1;
            if(save){entry=va;candidates++;}
        }
    }free(frequencies);
    if(candidates!=1){fprintf(stderr,"error: ARM32 resolver discovery found %u candidates\n",candidates);return -1;}
    uint32_t thumb_entry=UINT32_MAX;
    for(uint32_t distance=8;distance<=64&&distance<=entry;distance+=2){uint32_t off,va=entry-distance;int exchange=0;
        if(a32_offset(m,va,12,&off)||a32_u16(image+off)!=0xb500||a32_u16(image+off+6)!=0x4770)continue;
        uint32_t target=a32_thumb_call(image+off+2,va+2,&exchange);
        if(exchange&&target==va+8&&(a32_u32(image+off+8)&0xff000000u)==0xea000000u){
            if(thumb_entry!=UINT32_MAX){fprintf(stderr,"error: ambiguous ARM32 Thumb resolver wrapper\n");return -1;}thumb_entry=va|1u;
        }
    }
    a32_callsite *found=NULL;unsigned n=0;
    for(unsigned i=0;i<m->nseg;i++){const a32_segment *s=&m->seg[i];if(!(s->flags&1))continue;
        for(uint32_t j=0;j+4<=s->filesz;j+=2){uint32_t va=s->va+j,target=entry;int thumb=0,exchange=0;
            if(!(va&3)&&((target=a32_arm_call(a32_u32(image+s->off+j),va))==entry||(target==thumb_entry&&target!=UINT32_MAX)))thumb=0;
            else {target=a32_thumb_call(image+s->off+j,va,&exchange);if(target!=entry&&(target!=thumb_entry||target==UINT32_MAX))continue;thumb=1;}
            a32_callsite *next=realloc(found,(size_t)(n+1)*sizeof *found);if(!next){free(found);return -1;}found=next;
            uint32_t instruction=a32_u32(image+s->off+j),condition=(instruction&0xfe000000u)==0xfa000000u?14:instruction>>28;
            found[n++]=(a32_callsite){va,s->off+j,thumb,target,condition};
        }
    }
    if(!n){free(found);return -1;}*resolver=entry;*sites=found;*count=n;return 0;
}
static int a32_resolver_tail(const a32_image *m,const uint8_t *image,uint32_t resolver,uint32_t *tail){
    unsigned matches=0;
    for(unsigned i=0;i<m->nseg;i++){const a32_segment *s=&m->seg[i];
        if(!(s->flags&1)||resolver<s->va||resolver-s->va>=s->filesz)continue;
        for(uint32_t j=0;j+12<=s->filesz;j+=4){uint32_t pc=s->va+j;
            if(pc+16384<resolver||pc>resolver+16384)continue;
            if(a32_u32(image+s->off+j)!=0xe129f002u||a32_u32(image+s->off+j+4)!=0xe8bd5007u)continue;
            uint32_t branch=a32_u32(image+s->off+j+8);if((branch&0xff000000u)!=0xea000000u)continue;
            uint32_t target=pc+16+(uint32_t)(a32_sign(branch&0xffffff,24)*4),off;
            if(a32_offset(m,target,4,&off))continue;
            uint32_t pop=a32_u32(image+off);if(pop!=0xe8bd8000u&&pop!=0xe49df004u)continue;
            *tail=target;matches++;
        }
    }
    if(matches!=1){fprintf(stderr,"error: ARM32 resolver has %u supported tails\n",matches);return -1;}return 0;
}
typedef struct {a32_runtime *r;uint32_t destination,registers[16];uint64_t doubles[32];int found;} a32_resolution;
static void a32_resolved(uc_engine *uc,uint64_t pc,uint32_t size,void *user){
    a32_resolution *result=user;(void)size;(void)pc;
    result->found=1;
    uint32_t sp=a32_reg(result->r,UC_ARM_REG_SP);result->destination=a32_get(result->r,sp);
    for(unsigned i=0;i<16;i++)result->registers[i]=a32_reg(result->r,a32_trace_reg(i));
    result->registers[13]=sp+4; /* the observed POP {pc} consumes this target */
    for(unsigned i=0;i<32;i++)if(uc_reg_read(uc,UC_ARM_REG_D0+(int)i,&result->doubles[i]))a32_fail(result->r,"resolver VFP read");
    uc_emu_stop(uc);
}
static int a32_encode_call(uint8_t *out,const a32_callsite *site,uint32_t destination){
    if(!site->thumb){
        int64_t delta=(int64_t)(destination&~1u)-(site->site+8);
        if(delta<-(1LL<<25)||delta>=(1LL<<25)||(delta&1))return -1;
        uint32_t instruction;
        if(destination&1){if(site->condition!=14)return -1;instruction=0xfa000000u|((uint32_t)(delta&2)<<23)|((uint32_t)(delta>>2)&0xffffff);}
        else {if(delta&3||site->condition>14)return -1;instruction=(site->condition<<28)|0x0b000000u|((uint32_t)(delta>>2)&0xffffff);}
        a32_p32(out+site->file,instruction);return 0;
    }
    int exchange=!(destination&1);uint32_t base=exchange?(site->site+4)&~3u:site->site+4;
    int64_t delta=(int64_t)(destination&~1u)-base;if(delta<-(1LL<<24)||delta>=(1LL<<24)||(delta&(exchange?3:1)))return -1;
    uint32_t immediate=(uint32_t)delta,s=(immediate>>24)&1,i1=(immediate>>23)&1,i2=(immediate>>22)&1;
    uint16_t hi=(uint16_t)(0xf000|(s<<10)|((immediate>>12)&1023));
    uint16_t lo=(uint16_t)((exchange?0xc000:0xd000)|((1^i1^s)<<13)|((1^i2^s)<<11)|((immediate>>1)&2047));
    out[site->file]=(uint8_t)hi;out[site->file+1]=(uint8_t)(hi>>8);out[site->file+2]=(uint8_t)lo;out[site->file+3]=(uint8_t)(lo>>8);return 0;
}
static int a32_recover_calls(a32_runtime *r,uint8_t *out,uint32_t resolver,const a32_callsite *sites,unsigned count){
    a32_resolution result={.r=r};uc_hook hook;int status=-1;
    uint32_t tail;if(a32_resolver_tail(&r->game,out,resolver,&tail))return -1;
    if(uc_hook_add(r->uc,&hook,UC_HOOK_CODE,a32_resolved,&result,r->game.bias+tail,r->game.bias+tail))return -1;
    for(unsigned i=0;i<count;i++){
        uint32_t destinations[2];
        for(unsigned trial=0;trial<2;trial++){
            uint32_t registers[13],stack=A32_SP,lr=(r->game.bias+sites[i].site+4)|(sites[i].thumb?1u:0u);uint64_t doubles[32];
            for(unsigned reg=0;reg<13;reg++){registers[reg]=trial?0x11223344u+reg*0x1020304u:0;a32_set(r,UC_ARM_REG_R0+(int)reg,registers[reg]);}
            for(unsigned reg=0;reg<32;reg++){doubles[reg]=trial?0x1122334455667788ULL+reg*0x102030405ULL:0;
                if(uc_reg_write(r->uc,UC_ARM_REG_D0+(int)reg,&doubles[reg]))goto done;}
            a32_set(r,UC_ARM_REG_SP,stack);a32_set(r,UC_ARM_REG_LR,lr);result.found=0;
            uc_err err=uc_emu_start(r->uc,r->game.bias+sites[i].entry,0,0,1000000);
            if(err||r->failed||!result.found||result.registers[13]!=stack||result.registers[14]!=lr){
                fprintf(stderr,"error: ARM32 resolver frame/target failure at 0x%x (%s, target=%x sp=%x lr=%x)\n",sites[i].site,uc_strerror(err),result.destination,result.registers[13],result.registers[14]);goto done;
            }
            for(unsigned reg=0;reg<12;reg++)if(result.registers[reg]!=registers[reg]){
                fprintf(stderr,"error: ARM32 resolver changes r%u at 0x%x\n",reg,sites[i].site);goto done;}
            for(unsigned reg=0;reg<32;reg++)if(result.doubles[reg]!=doubles[reg]){
                fprintf(stderr,"error: ARM32 resolver changes d%u at 0x%x\n",reg,sites[i].site);goto done;}
            int executable=0;uint32_t address=result.destination&~1u;
            for(unsigned j=0;j<r->game.nseg;j++){a32_segment *segment=&r->game.seg[j];uint32_t start=r->game.bias+segment->va;
                if((segment->flags&1)&&address>=start&&address-start<segment->filesz)executable=1;
            }
            if(!executable||address==r->game.bias+resolver){fprintf(stderr,"error: ARM32 resolver target is not game code\n");goto done;}
            destinations[trial]=result.destination-r->game.bias;
        }
        if(destinations[0]!=destinations[1]||a32_encode_call(out,&sites[i],destinations[0])){
            fprintf(stderr,"error: ARM32 unstable/out-of-range call target at 0x%x\n",sites[i].site);goto done;}
        if((i+1)%1000==0)fprintf(stderr,"[*] ARM32 verified %u/%u resolver sites\n",i+1,count);
    }status=0;
done:uc_hook_del(r->uc,hook);return status;
}
static int a32_export_native(a32_runtime *r,const char *outdir){
    a32_image *m=&r->game;uint8_t *out=malloc(m->size),*reference=NULL,*patches=NULL;a32_callsite *sites=NULL;int result=-1;
    if(!out)return -1;
    memcpy(out,m->raw,m->size);size_t changed=0;
    for(unsigned i=0;i<m->nseg;i++){a32_segment *s=&m->seg[i];if(!(s->flags&1))continue;
        if(uc_mem_read(r->uc,m->bias+s->va,out+s->off,s->filesz))goto done;
        for(uint32_t j=0;j<s->filesz;j++)changed+=out[s->off+j]!=m->raw[s->off+j];
    }
    reference=malloc(m->size);if(!reference)goto done;memcpy(reference,out,m->size);
    uint32_t resolver;unsigned count;
    if(a32_find_resolver(m,out,&resolver,&sites,&count))goto done;
    fprintf(stderr,"[*] ARM32 resolver=0x%x callers=%u; verifying argument/register preservation\n",resolver,count);
    if(a32_recover_calls(r,out,resolver,sites,count))goto done;
    /* A resolver can materialize a stolen-prologue trampoline on first use.
     * Keep those executable bytes too, without overwriting verified branches. */
    patches=malloc((size_t)count*4);if(!patches)goto done;
    for(unsigned i=0;i<count;i++)memcpy(patches+i*4,out+sites[i].file,4);
    for(unsigned i=0;i<m->nseg;i++){a32_segment *s=&m->seg[i];if((s->flags&1)&&uc_mem_read(r->uc,m->bias+s->va,out+s->off,s->filesz))goto done;}
    for(unsigned i=0;i<count;i++)memcpy(out+sites[i].file,patches+i*4,4);
    /* Serialize original writable bytes and relocation addends, not emulator
     * addresses. Only executable segment changes and verified calls survive. */
    uint32_t tables[]={m->tags[17],m->tags[23]},sizes[]={m->tags[18],m->tags[2]};
    for(unsigned t=0;t<2;t++){uint32_t table;if(!sizes[t])continue;if(a32_offset(m,tables[t],sizes[t],&table))goto done;
        for(uint32_t i=0;i<sizes[t];i+=8){uint32_t p;
            if(!a32_offset(m,a32_u32(m->raw+table+i),4,&p))memcpy(out+p,m->raw+p,4);
        }
    }
    uint32_t init=m->tags[12],off;if(a32_offset(m,init&~1u,4,&off))goto done;
    a32_p32(out+off,init&1?0xbf004770u:0xe12fff1eu);a32_p32(out+24,0);
    char library[4096],refpath[4096],reportpath[4096],report[1024];
    if(snprintf(library,sizeof library,"%s/libg.unpacked.so",outdir)>=(int)sizeof library||
       snprintf(refpath,sizeof refpath,"%s/libg.decrypted-reference.bin",outdir)>=(int)sizeof refpath||
       snprintf(reportpath,sizeof reportpath,"%s/native-report.txt",outdir)>=(int)sizeof reportpath)goto done;
    int length=snprintf(report,sizeof report,"ARM32 native recovery\nshield JNI_OnLoad: 0x10002\npacked DT_INIT: returned\nchanged executable bytes: %zu\nverified direct calls: %u\nresolver: 0x%x\nverification: two distinct integer/VFP register sets per call; arguments, callee-saved registers, SP and LR preserved\nexport: original writable bytes/REL addends; decrypted executable segments; packed DT_INIT disabled\n",changed,count,resolver);
    if(length<0||length>=(int)sizeof report||mkdir(outdir,0755))goto done;
    if(native_write_new(library,out,m->size)||native_write_new(refpath,reference,m->size)||native_write_new(reportpath,report,(size_t)length))goto done;
    fprintf(stderr,"[+] wrote %s (%u verified ARM32 calls)\n",library,count);result=0;
done:free(out);free(reference);free(patches);free(sites);return result;
}
static void a32_free(a32_runtime *r){
    for(unsigned i=0;i<64;i++)free(r->file_owned[i]);
    for(unsigned i=0;i<r->njump;i++)uc_context_free(r->jumps[i].cpu);
    for(unsigned i=0;i<16;i++)if(r->inflaters[i].active)inflateEnd(&r->inflaters[i].stream);
    for(unsigned i=0;i<r->nthread;i++){
        if(r->threads[i].cpu)uc_context_free(r->threads[i].cpu);
        a32_memory_free(r->threads[i].memory,r->threads[i].nmemory);
    }
    if(r->uc)uc_close(r->uc);
    apk_metadata_free(&r->metadata);
    free(r->shield.raw);free(r->game.raw);free(r->apk);free(r);
}
typedef struct {a32_runtime *r;uint8_t *data;size_t size;} a32_capture;
static void a32_capture_context(uc_engine *uc,uint64_t pc,uint32_t size,void *user){
    a32_capture *capture=user;a32_runtime *r=capture->r;(void)size;
    uint32_t length=a32_reg(r,UC_ARM_REG_R2);
    if(length<0x574||length>1048576||(length-4-0x170)%0x400||capture->data)return;
    uint8_t code[4];if(uc_mem_read(uc,pc,code,4))return;
    uint32_t word=a32_u32(code);int call;
    if(a32_reg(r,UC_ARM_REG_CPSR)&32){
        int exchange=0;call=a32_thumb_call(code,(uint32_t)pc,&exchange)!=UINT32_MAX||
            (a32_u16(code)&0xff87)==0x4780;
    }else call=a32_arm_call(word,(uint32_t)pc)!=UINT32_MAX||(word&0x0ffffff0)==0x012fff30;
    if(!call)return;
    uint8_t *data=malloc(length-4);if(!data)return;
    if(uc_mem_read(uc,a32_reg(r,UC_ARM_REG_R1),data,length-4)||!ctx_plausible(data,(int)length-4)){free(data);return;}
    capture->data=data;capture->size=length-4;uc_emu_stop(uc);
}
static int a32_generator(const uint8_t *code,size_t size){
    if(size<8||a32_u16(code)!=0xb5b0||a32_u16(code+2)!=0xaf02)return 0;
    uint32_t hi=a32_u16(code+4),lo=a32_u16(code+6);
    if((hi&0xfbff)!=0xf1ad||(lo&0x8f00)!=0x0d00)return 0;
    uint32_t immediate=((hi>>10)&1)<<11|((lo>>12)&7)<<8|(lo&255);
    if(immediate<0x400)return 0;
    unsigned rotation=immediate>>7;uint32_t value=0x80|(immediate&127);
    value=(value>>rotation)|(value<<(32-rotation));return value>=0x4000&&value<=1048576;
}
static int a32_load(a32_runtime *r,const char *shield,const char *apk,const char *game);
static int a32_context_run_with_apk(const char *so_path,const char *outdir,int verbose,const char *apk){
    a32_runtime *r=calloc(1,sizeof *r);if(!r)return -1;int written=0,result=-1;
    r->verbose=verbose;r->shield.name=native_name(so_path);
    r->game.name="libg.so";strcpy(r->metadata.package,"org.test");strcpy(r->metadata.version,"1");
    if(apk){if(a32_load(r,so_path,apk,NULL))goto done;}
    else if(native_blob(so_path,&r->shield.raw,&r->shield.size)||a32_parse(&r->shield)||a32_initialize(r)||a32_constructors(r,&r->shield))goto done;
    uint32_t entries[64];unsigned count=0;
    for(unsigned i=0;i<r->shield.nseg;i++){
        a32_segment *s=&r->shield.seg[i];if(!(s->flags&1))continue;
        uint8_t *code=malloc(s->filesz);if(!code)goto done;
        if(uc_mem_read(r->uc,s->va,code,s->filesz)){free(code);goto done;}
        for(uint32_t off=0;off+8<=s->filesz;off+=2)if(a32_generator(code+off,s->filesz-off)){
            if(count==64){free(code);goto done;}entries[count++]=(s->va+off)|1u;
        }
        free(code);
    }
    fprintf(stderr,"[*] ARM32 context generator candidates: %u\n",count);
    if(!count&&!apk)fprintf(stderr,"error: ARM32 startup may require its matching base APK; pass --apk base.apk\n");
    a32_capture capture={.r=r};uc_hook hook;
    if(uc_hook_add(r->uc,&hook,UC_HOOK_CODE,a32_capture_context,&capture,1,0))goto done;
    for(unsigned i=0;i<count;i++){
        for(unsigned reg=0;reg<13;reg++)a32_set(r,UC_ARM_REG_R0+(int)reg,0);
        a32_set(r,UC_ARM_REG_SP,A32_SP);a32_set(r,UC_ARM_REG_LR,A32_STOP);
        uc_err err=uc_emu_start(r->uc,entries[i],A32_STOP,0,4000000);
        if(capture.data){
            char path[4096];int length=snprintf(path,sizeof path,"%s/ctx_%x_%d.bin",outdir,entries[i],written);
            int ok=length>=0&&length<(int)sizeof path&&!native_write_new(path,capture.data,capture.size);
            free(capture.data);capture.data=NULL;if(!ok)break;
            fprintf(stderr,"[+] ARM32 context candidate: %s\n",path);written++;
        }else if(err||r->failed)break;
    }
    uc_hook_del(r->uc,hook);result=written?written:-1;
done:
    if(result<0)fprintf(stderr,"error: ARM32 context recovery failed\n");
    a32_free(r);return result;
}
static int a32_context_run(const char *so_path,const char *outdir,int verbose){return a32_context_run_with_apk(so_path,outdir,verbose,NULL);}
static int a32_load(a32_runtime *r,const char *shield,const char *apk,const char *game){
    r->game.bias=0x1000000;
    r->shield.name=native_name(shield);r->game.name=game?native_name(game):"libg.so";
    if(native_blob(shield,&r->shield.raw,&r->shield.size)||native_blob(apk,&r->apk,&r->apk_size)||
       apk_read_metadata(r->apk,r->apk_size,&r->metadata)||a32_parse(&r->shield)||
       (game&&(native_blob(game,&r->game.raw,&r->game.size)||a32_parse(&r->game)))||a32_initialize(r))return -1;
    if(a32_constructors(r,&r->shield))return -1;
    uint32_t jni=a32_export(&r->shield,"JNI_OnLoad");
    return !jni||a32_call(r,jni,A32_VM,0,0)||a32_reg(r,UC_ARM_REG_R0)!=0x10002?-1:0;
}
static int a32_method(a32_runtime *r,const char *owner,const char *signature,uint32_t *function){
    unsigned matches=0;char cls[1024],sig[1024];
    for(unsigned i=0;i<r->nnative;i++){
        if(a32_string(r,r->natives[i].owner,cls,sizeof cls)||a32_string(r,r->natives[i].signature,sig,sizeof sig))return -1;
        if((!owner||!strcmp(owner,cls))&&!strcmp(signature,sig)){*function=r->natives[i].function;matches++;}
    }
    return matches==1?0:-1;
}
static int a32_strings(const char *shield,const char *apk,const char *owner,uint32_t registration,const char *ids,const char *output){
    a32_runtime *r=calloc(1,sizeof *r);if(!r)return -1;
    FILE *in=NULL,*out=NULL;int result=-1;struct stat st;uint32_t registrar,function;
    if(!lstat(output,&st)||errno!=ENOENT||a32_load(r,shield,apk,NULL)||
       a32_method(r,NULL,"(Ljava/lang/Class;I)V",&registrar)||
       a32_call4(r,registrar,A32_ENV,0,a32_cstr(r,owner),registration)||
       a32_method(r,owner,"(I)Ljava/lang/String;",&function))goto done;
    in=fopen(ids,"r");if(!in)goto done;
    int fd=open(output,O_WRONLY|O_CREAT|O_EXCL,0644);if(fd<0)goto done;
    out=fdopen(fd,"w");if(!out){close(fd);unlink(output);goto done;}
    unsigned id,count=0;char value[65536];
    while(fscanf(in,"%x",&id)==1){
        if(++count>65536||a32_call4(r,function,A32_ENV,0,id,0)||!a32_reg(r,UC_ARM_REG_R0)||
           a32_string(r,a32_reg(r,UC_ARM_REG_R0),value,sizeof value))goto done;
        fprintf(out,"%08x\t",id);
        for(size_t j=0;value[j];j++)fprintf(out,"%02x",(unsigned char)value[j]);
        fputc('\n',out);
    }
    if(feof(in)&&count&&!ferror(in)&&!ferror(out))result=0;
done:
    if(in)fclose(in);
    if(out){if(fclose(out))result=-1;if(result)unlink(output);}
    if(result)fprintf(stderr,"error: ARM32 sparse string recovery failed\n");
    a32_free(r);return result;
}
static int native_is_arm32(const char *path){
    FILE *f=fopen(path,"rb");uint8_t ident[20];if(!f)return 0;
    size_t n=fread(ident,1,sizeof ident,f);fclose(f);
    return n==sizeof ident&&!memcmp(ident,"\177ELF\1\1",6)&&a32_u16(ident+18)==40;
}
int ctxgen_run_apk(const char *shield,const char *outdir,int verbose,const char *apk){
    if(!native_is_arm32(shield))return ctxgen_run(shield,outdir,verbose);
    if(mkdir(outdir,0755)&&errno!=EEXIST)return -1;
    return a32_context_run_with_apk(shield,outdir,verbose,apk);
}
static int arm32_native_unpack(const char *game,const char *shield,const char *apk,const char *outdir,int verbose){
    a32_runtime *r=calloc(1,sizeof *r);if(!r)return -1;int result=-1;struct stat st;
    r->verbose=verbose;
    if(!lstat(outdir,&st)||errno!=ENOENT){fprintf(stderr,"error: native output directory must not exist\n");goto done;}
    fprintf(stderr,"[*] ARM32 shield startup\n");
    if(a32_load(r,shield,apk,game)){fprintf(stderr,"error: ARM32 inputs or shield startup failed\n");goto done;}
    fprintf(stderr,"[*] ARM32 game constructors\n");
    if(!r->game.tags[12]||a32_call(r,r->game.bias+r->game.tags[12],0,0,0))goto done;
    result=a32_export_native(r,outdir);
done:
    a32_free(r);return result;
}


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
    if(image->symnames)for(int i=0;i<image->nsyms;i++)free(image->symnames[i]);
    free(image->symnames);free(image->raw);free(image->apk);apk_metadata_free(&image->package);
}
static const char *native_name(const char *path){const char *p=strrchr(path,'/');return p?p+1:path;}
static int native_load(emu_t *host,const char *shield,const char *apk,emu_t *game,const char *library){
    if(native_blob(shield,&host->raw,&host->raw_len)||native_blob(apk,&host->apk,&host->apk_len)||
       apk_read_metadata(host->apk,host->apk_len,&host->package)||elf_load(host))return -1;
    host->image_name=native_name(shield);elf_syms(host);if(!host->nsyms)return -1;
    if(game){
        if(native_blob(library,&game->raw,&game->raw_len)||elf_load(game))return -1;
        game->image_name=native_name(library);elf_syms(game);if(!game->nsyms)return -1;
        for(int i=0;i<host->nsegs;i++)if(host->segs[i].va>=0x1000000||host->segs[i].memsz>0x1000000-host->segs[i].va)return -1;
        for(int i=0;i<game->nsegs;i++)if(game->segs[i].va>=0x2000000||game->segs[i].memsz>0x2000000-game->segs[i].va)return -1;
    }
    if(uc_open(UC_ARCH_ARM64,UC_MODE_LITTLE_ENDIAN,&host->uc)||emu_map(host)||apply_relocations(host))return -1;
    if(game){
        game->uc=host->uc;game->load_bias=0x1000000;game->imports=host;host->peer=game;
        if(emu_map(game)||apply_relocations(game))return -1;
    }
    uint64_t tls=TLS_BASE,canary=0x1122334455667788ULL;
    uc_reg_write(host->uc,UC_ARM64_REG_TPIDR_EL0,&tls);uc_mem_write(host->uc,TLS_BASE+0x28,&canary,8);
    host->heap_next=HEAP_BASE+0x1000;host->mmap_next=MMAP_BASE;host->errno_addr=MISC_BASE+0x1000;
    host->next_fd=0x200;host->file_next=MISC_BASE+0x4000;host->startup_budget=3000000000ULL;
    return 0;
}
static int native_boot(emu_t *host,emu_t *game,native_probe_state_t *probes){
    memset(probes,0,sizeof *probes);probes->host=host;
    uc_hook observer;
    if(game&&uc_hook_add(host->uc,&observer,UC_HOOK_BLOCK,native_probe_observer,probes,1,0))return -1;
    if(run_unpack(host)||host->stop||rdreg(host->uc,R_PC)!=SENT_JNI||rdreg(host->uc,R_X0)!=0x10002){
        fprintf(stderr,"error: shield initialization did not complete (stop=%d, pc=0x%llx, JNI version=0x%llx)\n",
                host->stop,(unsigned long long)rdreg(host->uc,R_PC),(unsigned long long)rdreg(host->uc,R_X0));return -1;
    }
    return game?native_constructor(host,game->load_bias+dyn_value(game,12)):0;
}
int ctxgen_native_unpack(const char *game_path,const char *shield_path,const char *apk_path,const char *outdir,int verbose){
    if(native_is_arm32(game_path))return arm32_native_unpack(game_path,shield_path,apk_path,outdir,verbose);
    emu_t *host=calloc(1,sizeof *host),*game=calloc(1,sizeof *game);uint8_t *out=NULL,*reference=NULL;int result=-1;
    if(!host||!game){free(host);free(game);return -1;}g_verbose=verbose;
    struct stat st;native_probe_state_t probes;
    if(!lstat(outdir,&st)||errno!=ENOENT){fprintf(stderr,"error: native output directory must not exist\n");goto done;}
    if(native_load(host,shield_path,apk_path,game,game_path)||native_boot(host,game,&probes))goto done;
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
static int native_method(const emu_t *e,const char *owner,const char *signature,uint64_t *function){
    unsigned count=0;
    for(unsigned i=0;i<e->nnatives;i++)if((!owner||!strcmp(e->natives[i].owner,owner))&&
       !strcmp(e->natives[i].signature,signature)){*function=e->natives[i].function;count++;}
    return count==1?0:-1;
}
static int native_register(emu_t *e,const char *owner,uint32_t id,const char *signature,uint64_t *function){
    uint64_t registrar;
    if(native_method(e,NULL,"(Ljava/lang/Class;I)V",&registrar))return -1;
    uint64_t clazz=heap_alloc(e,strlen(owner)+1,0);if(!clazz)return -1;write_cstr(e,clazz,owner);
    return native_jni_call(e,registrar,clazz,id)||native_method(e,owner,signature,function)?-1:0;
}
int ctxgen_strings(const char *shield,const char *apk,const char *owner,uint32_t registration,const char *ids,const char *output){
    if(native_is_arm32(shield))return a32_strings(shield,apk,owner,registration,ids,output);
    emu_t *e=calloc(1,sizeof *e);FILE *in=NULL,*out=NULL;int result=-1;char *value=NULL;
    if(!e)return -1;
    struct stat st;if(!lstat(output,&st)||errno!=ENOENT)goto done;
    native_probe_state_t probes;uint64_t function;
    if(native_load(e,shield,apk,NULL,NULL)||native_boot(e,NULL,&probes)||
       native_register(e,owner,registration,"(I)Ljava/lang/String;",&function))goto done;
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
