/* ZIP and Android binary-XML metadata reader. No extraction to the filesystem. */
#include "apk.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <zlib.h>

static uint16_t u16(const uint8_t *p){return (uint16_t)(p[0]|p[1]<<8);}
static uint32_t u32(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint64_t u64(const uint8_t *p){return u32(p)|(uint64_t)u32(p+4)<<32;}
static int directory(const uint8_t *b,size_t n,size_t *offset,size_t *size,unsigned *count){
    if(n<22)return -1;
    size_t min=n>65557?n-65557:0;
    for(size_t i=n-22;;i--){
        if(u32(b+i)==0x06054b50 && i+22+u16(b+i+20)==n){
            if(u16(b+i+4)||u16(b+i+6)||u16(b+i+8)!=u16(b+i+10))return -1;
            *offset=u32(b+i+16);*size=u32(b+i+12);*count=u16(b+i+10);
            if(*offset>i || *size>i-*offset)return -1;
            return 0;
        }
        if(i==min)break;
    }
    return -1;
}
int apk_entry(const uint8_t *b,size_t n,const char *name,uint8_t **out,size_t *outlen){
    size_t cd,sz;unsigned count;*out=NULL;*outlen=0;
    if(directory(b,n,&cd,&sz,&count))return -1;
    size_t end=cd+sz,want=strlen(name);
    for(unsigned i=0;i<count;i++){
        if(cd>end || end-cd<46 || u32(b+cd)!=0x02014b50)return -1;
        unsigned nl=u16(b+cd+28),xl=u16(b+cd+30),cl=u16(b+cd+32);
        size_t next=cd+46+(size_t)nl+xl+cl;if(next>end)return -1;
        if(nl==want && !memcmp(b+cd+46,name,nl)){
            uint32_t packed=u32(b+cd+20),plain=u32(b+cd+24),local=u32(b+cd+42);
            unsigned method=u16(b+cd+10);
            if((u16(b+cd+8)&1)||plain>128u*1024*1024||local>n||n-local<30||u32(b+local)!=0x04034b50)return -1;
            size_t off=(size_t)local+30+u16(b+local+26)+u16(b+local+28);
            if(off>n||packed>n-off)return -1;
            uint8_t *p=malloc((size_t)plain+1);if(!p)return -1;
            if(method==0){if(packed!=plain){free(p);return -1;}memcpy(p,b+off,plain);}
            else if(method==8){
                z_stream z={0};z.next_in=(Bytef *)(b+off);z.avail_in=packed;z.next_out=p;z.avail_out=plain+1;
                if(inflateInit2(&z,-MAX_WBITS)!=Z_OK){free(p);return -1;}
                int rc=inflate(&z,Z_FINISH);int valid=rc==Z_STREAM_END&&z.total_out==plain&&z.total_in==packed;
                inflateEnd(&z);if(!valid){free(p);return -1;}
            }else{free(p);return -1;}
            if((uint32_t)crc32(0,p,plain)!=u32(b+cd+16)){free(p);return -1;}
            p[plain]=0;*out=p;*outlen=plain;return 0;
        }
        cd=next;
    }
    return -1;
}
static int length8(const uint8_t **p,const uint8_t *end,size_t *n){
    if(*p==end)return -1;
    unsigned a=*(*p)++;
    if(a&128){if(*p==end)return -1;*n=((a&127)<<8)|*(*p)++;}else *n=a;
    return 0;
}
static int pool_string(const uint8_t *pool,size_t len,uint32_t id,char *out,size_t cap){
    if(len<28||u16(pool+2)<28||id>=u32(pool+8)||!cap)return -1;
    size_t header=u16(pool+2),start=u32(pool+20);
    if(header>len || id>=(len-header)/4 || start>len)return -1;
    uint32_t off=u32(pool+header+(size_t)id*4);if(off>=len-start)return -1;
    const uint8_t *p=pool+start+off,*end=pool+len;size_t n;
    if(u32(pool+16)&256){
        if(length8(&p,end,&n)||length8(&p,end,&n)||n>=(size_t)(end-p)||n>=cap||p[n])return -1;
        memcpy(out,p,n);out[n]=0;return 0;
    }
    if(end-p<2)return -1;
    n=u16(p);p+=2;
    if(n&0x8000){if(end-p<2)return -1;n=((n&0x7fff)<<16)|u16(p);p+=2;}
    if(n>(size_t)(end-p)/2 || n>=cap)return -1;
    /* Metadata used here is ASCII; reject instead of silently mangling UTF-16. */
    for(size_t i=0;i<n;i++){unsigned ch=u16(p+i*2);if(ch>127)return -1;out[i]=(char)ch;}
    out[n]=0;return 0;
}
static int manifest(const uint8_t *b,size_t n,struct apk_metadata *out){
    if(n<8||u16(b)!=3||u16(b+2)!=8||u32(b+4)!=n)return -1;
    const uint8_t *pool=NULL;size_t plen=0;
    for(size_t off=8;off<n;){
        if(n-off<8)return -1;
        size_t size=u32(b+off+4),header=u16(b+off+2);
        if(size<8||size>n-off||header>size)return -1;
        if(u16(b+off)==1){pool=b+off;plen=size;}
        if(u16(b+off)==0x102 && pool){
            const uint8_t *node=b+off;
            if(header<16||size-header<20)return -1;
            const uint8_t *ext=node+header;char tag[64];
            if(pool_string(pool,plen,u32(ext+4),tag,sizeof tag))return -1;
            int is_manifest=!strcmp(tag,"manifest"),is_service=!strcmp(tag,"service");
            if(is_manifest || is_service){
                if(is_service && out->nservices>=128)return -1;
                unsigned service=out->nservices;
                size_t attrs=header+u16(ext+8),stride=u16(ext+10),count=u16(ext+12);
                if(stride<20||attrs>size||count>(size-attrs)/stride)return -1;
                for(size_t i=0;i<count;i++){
                    const uint8_t *a=node+attrs+i*stride;char key[128],value[512];
                    if(pool_string(pool,plen,u32(a+4),key,sizeof key))return -1;
                    uint32_t id=u32(a+8);if(id==UINT32_MAX && a[15]==3)id=u32(a+16);
                    value[0]=0;if(id!=UINT32_MAX && pool_string(pool,plen,id,value,sizeof value))return -1;
                    if(is_manifest){
                        if(!strcmp(key,"package")){if(strlen(value)>=sizeof out->package)return -1;strcpy(out->package,value);}
                        if(!strcmp(key,"versionName")){if(strlen(value)>=sizeof out->version)return -1;strcpy(out->version,value);}
                        if(!strcmp(key,"versionCode"))out->version_code=u32(a+16);
                    }else if(!strcmp(key,"name")){
                        char full[512];
                        int len=value[0]=='.'?snprintf(full,sizeof full,"%s%s",out->package,value):
                            !strchr(value,'.')?snprintf(full,sizeof full,"%s.%s",out->package,value):snprintf(full,sizeof full,"%s",value);
                        if(len<0 || len>=(int)sizeof out->services[service].name)return -1;
                        strcpy(out->services[service].name,full);
                    }else if(!strcmp(key,"permission")){
                        if(strlen(value)>=sizeof out->services[service].permission)return -1;
                        strcpy(out->services[service].permission,value);
                    }
                }
                if(is_service){if(!*out->services[service].name)return -1;out->nservices++;}
            }
        }
        off+=size;
    }
    return *out->package && *out->version ? 0 : -1;
}
static int slice32(const uint8_t **p,const uint8_t *end,const uint8_t **data,size_t *len){
    if(end-*p<4)return -1;
    *len=u32(*p);*p+=4;if(*len>(size_t)(end-*p))return -1;
    *data=*p;*p+=*len;return 0;
}
static void signing_certificate(const uint8_t *b,size_t n,struct apk_metadata *out){
    size_t cd,sz;unsigned count;if(directory(b,n,&cd,&sz,&count)||cd<32)return;
    if(memcmp(b+cd-16,"APK Sig Block 42",16))return;
    uint64_t block=u64(b+cd-24);if(block<24||block>cd-8)return;
    size_t start=cd-(size_t)block-8;if(u64(b+start)!=block)return;
    for(size_t p=start+8;p<cd-24;){
        if(cd-24-p<12)return;
        uint64_t len=u64(b+p);p+=8;
        if(len<4||len>cd-24-p)return;
        if(u32(b+p)==0x7109871a){
            const uint8_t *v=b+p+4,*end=b+p+(size_t)len,*seq,*signed_data,*digests,*certs,*cert;size_t sn,dn,cn,certlen;
            if(slice32(&v,end,&seq,&sn))return;
            v=seq;end=seq+sn;if(slice32(&v,end,&seq,&sn))return;
            v=seq;end=seq+sn;if(slice32(&v,end,&signed_data,&sn))return;
            v=signed_data;end=v+sn;
            if(slice32(&v,end,&digests,&dn)||slice32(&v,end,&certs,&cn))return;
            v=certs;end=v+cn;if(slice32(&v,end,&cert,&certlen)||!certlen)return;
            out->certificate=malloc(certlen);if(!out->certificate)return;
            memcpy(out->certificate,cert,certlen);out->certificate_len=certlen;return;
        }
        p+=(size_t)len;
    }
}
int apk_read_metadata(const uint8_t *b,size_t n,struct apk_metadata *out){
    memset(out,0,sizeof *out);uint8_t *xml;size_t len;
    if(apk_entry(b,n,"AndroidManifest.xml",&xml,&len))return -1;
    int rc=manifest(xml,len,out);free(xml);if(rc)return -1;
    signing_certificate(b,n,out);return 0;
}
void apk_metadata_free(struct apk_metadata *out){free(out->certificate);memset(out,0,sizeof *out);}
