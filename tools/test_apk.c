#include "../src/apk.c"
#include <assert.h>
#include <stdio.h>

static void w16(uint8_t *b,size_t off,uint16_t v){b[off]=(uint8_t)v;b[off+1]=(uint8_t)(v>>8);}
static void w32(uint8_t *b,size_t off,uint32_t v){for(int i=0;i<4;i++)b[off+i]=(uint8_t)(v>>(8*i));}
static size_t xml_fixture(uint8_t *b){
    const char *strings[]={"manifest","package","versionName","versionCode","test.package","1.2",
                          "service","name",".Service","permission","test.permission"};
    size_t pool=8,start=28+11*4,pos=pool+start;
    w16(b,0,3);w16(b,2,8);w16(b,pool,1);w16(b,pool+2,28);
    w32(b,pool+8,11);w32(b,pool+16,256);w32(b,pool+20,(uint32_t)start);
    for(unsigned i=0;i<11;i++){
        size_t n=strlen(strings[i]);w32(b,pool+28+i*4,(uint32_t)(pos-pool-start));
        b[pos++]=(uint8_t)n;b[pos++]=(uint8_t)n;memcpy(b+pos,strings[i],n+1);pos+=n+1;
    }
    pos=(pos+3)&~(size_t)3;w32(b,pool+4,(uint32_t)(pos-pool));
    size_t node=pos;w16(b,node,0x102);w16(b,node+2,16);w32(b,node+4,96);
    w32(b,node+16,UINT32_MAX);w32(b,node+20,0);w16(b,node+24,20);w16(b,node+26,20);w16(b,node+28,3);
    for(unsigned i=0;i<3;i++){
        size_t a=node+36+i*20;w32(b,a,UINT32_MAX);w32(b,a+4,i+1);
        w32(b,a+8,i<2?i+4:UINT32_MAX);w16(b,a+12,8);b[a+15]=i<2?3:0x10;w32(b,a+16,i<2?i+4:12);
    }
    pos+=96;node=pos;w16(b,node,0x102);w16(b,node+2,16);w32(b,node+4,76);
    w32(b,node+16,UINT32_MAX);w32(b,node+20,6);w16(b,node+24,20);w16(b,node+26,20);w16(b,node+28,2);
    for(unsigned i=0;i<2;i++){
        size_t a=node+36+i*20;w32(b,a,UINT32_MAX);w32(b,a+4,7+i*2);w32(b,a+8,8+i*2);
        w16(b,a+12,8);b[a+15]=3;w32(b,a+16,8+i*2);
    }
    pos+=76;w32(b,4,(uint32_t)pos);return pos;
}
static size_t zip_fixture(uint8_t *b,const uint8_t *xml,size_t n){
    const char *name="AndroidManifest.xml";size_t nl=strlen(name);
    w32(b,0,0x04034b50);w16(b,4,20);w32(b,14,(uint32_t)crc32(0,xml,(uInt)n));
    w32(b,18,(uint32_t)n);w32(b,22,(uint32_t)n);w16(b,26,(uint16_t)nl);memcpy(b+30,name,nl);memcpy(b+30+nl,xml,n);
    size_t cd=30+nl+n;w32(b,cd,0x02014b50);w16(b,cd+4,20);w16(b,cd+6,20);
    w32(b,cd+16,(uint32_t)crc32(0,xml,(uInt)n));w32(b,cd+20,(uint32_t)n);w32(b,cd+24,(uint32_t)n);w16(b,cd+28,(uint16_t)nl);
    memcpy(b+cd+46,name,nl);size_t end=cd+46+nl;w32(b,end,0x06054b50);
    w16(b,end+8,1);w16(b,end+10,1);w32(b,end+12,(uint32_t)(end-cd));w32(b,end+16,(uint32_t)cd);return end+22;
}
int main(void){
    uint8_t xml[1024]={0},zip[2048]={0};size_t xn=xml_fixture(xml),zn=zip_fixture(zip,xml,xn);
    struct apk_metadata m;assert(!apk_read_metadata(zip,zn,&m));
    assert(!strcmp(m.package,"test.package")&&!strcmp(m.version,"1.2")&&m.version_code==12);
    assert(m.nservices==1 && !strcmp(m.services[0].name,"test.package.Service") && !strcmp(m.services[0].permission,"test.permission"));
    apk_metadata_free(&m);
    uint8_t *out=NULL;size_t n=0;assert(!apk_entry(zip,zn,"AndroidManifest.xml",&out,&n));assert(n==xn&&!memcmp(out,xml,n));free(out);
    zip[50]^=1;assert(apk_read_metadata(zip,zn,&m)<0);zip[50]^=1;
    for(size_t i=0;i<zn;i++)assert(apk_read_metadata(zip,i,&m)<0);
    assert(apk_entry(zip,zn,"missing",&out,&n)<0);
    puts("PASS: APK ZIP bounds/CRC, binary XML metadata, truncation and missing entries");return 0;
}
