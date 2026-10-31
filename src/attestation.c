/* Token mathematics only. Build-specific material must come from the caller's
 * libraries; there are deliberately no sample keys, IVs or codec multipliers. */
#include "attestation.h"
#include "lbts.h"
#include <string.h>

static uint64_t get64(const uint8_t *b){
    uint64_t value=0;for(unsigned i=0;i<8;i++)value|=(uint64_t)b[i]<<(8*i);return value;
}
static void put64(uint8_t *b,uint64_t value){for(unsigned i=0;i<8;i++)b[i]=(uint8_t)(value>>(8*i));}

void attestation_custom_sha(const uint8_t state[32],const uint8_t *data,size_t length,uint8_t digest[32]){
    sha256_ctx ctx;memset(&ctx,0,sizeof ctx);
    for(unsigned i=0;i<8;i++)for(unsigned j=0;j<4;j++)ctx.s[i]|=(uint32_t)state[i*4+j]<<(8*j);
    ctx.len=sizeof ctx.buf; /* supplied state follows one compressed SHA block */
    sha256_update(&ctx,data,length);sha256_final(&ctx,digest);
}
static void fold(const attestation_material *m,const uint8_t *data,size_t length,uint8_t out[32]){
    uint8_t inner[32];attestation_custom_sha(m->primary,data,length,inner);
    attestation_custom_sha(m->secondary,inner,sizeof inner,out);
}
static void qualifier(uint64_t flag,uint8_t bits,uint8_t digest[32]){
    uint8_t block[9];put64(block,flag);block[8]=bits;sha256(block,sizeof block,digest);
}
static void hmac(const uint8_t key[32],const uint8_t data[32],uint8_t out[32]){
    uint8_t block[64],inner[32];sha256_ctx ctx;
    memset(block,0x36,sizeof block);for(unsigned i=0;i<32;i++)block[i]^=key[i];
    sha256_init(&ctx);sha256_update(&ctx,block,sizeof block);sha256_update(&ctx,data,32);sha256_final(&ctx,inner);
    memset(block,0x5c,sizeof block);for(unsigned i=0;i<32;i++)block[i]^=key[i];
    sha256_init(&ctx);sha256_update(&ctx,block,sizeof block);sha256_update(&ctx,inner,sizeof inner);sha256_final(&ctx,out);
}
int attestation_compute(const attestation_material *m,const uint8_t request[32],uint64_t time,
                        const uint8_t seed[8],uint8_t token[80]){
    if(!m||!request||!seed||!token||!m->multiplier)return -1;
    uint64_t raw[4],words[4];uint8_t key[32],grouped[64],folded[64],digest[32];size_t ng=0,nf=0;
    for(unsigned i=0;i<4;i++)raw[i]=get64(request+i*8);
    words[0]=raw[0];for(unsigned i=1;i<4;i++)words[i]=raw[i]-m->multiplier*raw[i-1];
    for(unsigned i=0;i<4;i++)put64(key+i*8,words[i]);
    uint8_t bits=(uint8_t)(words[2]&14);
    if(words[2]&2){qualifier(2,bits,grouped+ng);ng+=32;}
    if(words[2]&4){qualifier(4,bits,grouped+ng);ng+=32;}
    if(ng){fold(m,grouped,ng,folded+nf);nf+=32;}
    if(words[2]&8){qualifier(8,bits,grouped);fold(m,grouped,32,folded+nf);nf+=32;}
    fold(m,folded,nf,digest);hmac(key,digest,digest);
    uint64_t previous=get64(seed);put64(token,previous);
    uint64_t payload[9]={time,words[0],words[1],words[2],words[3],0,0,0,0};
    for(unsigned i=0;i<4;i++)payload[i+5]=get64(digest+i*8);
    for(unsigned i=0;i<9;i++){previous=previous*m->multiplier+payload[i];put64(token+8*(i+1),previous);}
    return 0;
}
