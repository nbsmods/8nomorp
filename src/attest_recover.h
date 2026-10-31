/* Material discovery observes argument/return values, not build addresses.
 * A candidate state is accepted only after a native finalizer returns the same
 * digest as independent SHA-256 continuation from that state. */
#ifndef ATTEST_RECOVER_H
#define ATTEST_RECOVER_H
#include "attestation.h"
typedef struct {uint8_t iv[32],digest[32];uint64_t updater;unsigned verified;} attest_state;
typedef struct {uint64_t address;unsigned state;uint8_t data[128];size_t length;} attest_context;
typedef struct {uint64_t pc,out;unsigned state;uint8_t expected[32];int used;} attest_pending;
typedef struct {
    emu_t *host;attest_state states[8];unsigned nstates;
    attest_context contexts[16];unsigned ncontexts;
    attest_pending pending[64];unsigned edges[8][8];int failed;
} attest_capture;

static void attest_capture_code(uc_engine *uc,uint64_t pc,uint32_t size,void *ud){
    (void)size;attest_capture *c=ud;
    for(unsigned i=0;i<64;i++)if(c->pending[i].used&&c->pending[i].pc==pc){
        attest_pending *p=&c->pending[i];uint8_t actual[32];p->used=0;
        if(!uc_mem_read(uc,p->out,actual,sizeof actual)&&!memcmp(actual,p->expected,sizeof actual)){
            attest_state *s=&c->states[p->state];s->verified++;memcpy(s->digest,actual,32);
        }
    }
    uint32_t word;if(uc_mem_read(uc,pc,&word,4))return;
    if((word&0xfc000000u)!=0x94000000u)return; /* the audited path uses direct BLs */
    uint64_t target=pc+native_branch_delta(word);
    if(!native_executable(c->host,target))return;
    uint64_t a0=rdreg(uc,R_X0),a1=rdreg(uc,R_X1),n=rdreg(uc,R_X2);
    uint8_t state[112];
    if(a0&&n<=128&&!uc_mem_read(uc,a0,state,sizeof state)&&rd64(state,32)==64*8&&rd32(state,104)==0){
        uint8_t data[128];
        if(n&&(!a1||uc_mem_read(uc,a1,data,(size_t)n)))return;
        unsigned si;
        for(si=0;si<c->nstates;si++)if(!memcmp(c->states[si].iv,state,32)&&c->states[si].updater==target)break;
        if(si==c->nstates){
            if(si>=8){c->failed=1;return;}
            memcpy(c->states[si].iv,state,32);c->states[si].updater=target;c->nstates++;
        }
        unsigned ci;for(ci=0;ci<c->ncontexts;ci++)if(c->contexts[ci].address==a0)break;
        if(ci==c->ncontexts){if(ci>=16){c->failed=1;return;}c->ncontexts++;}
        c->contexts[ci].address=a0;c->contexts[ci].state=si;c->contexts[ci].length=0;
        if(n==32)for(unsigned prev=0;prev<c->nstates;prev++)
            if(prev!=si&&c->states[prev].verified&&!memcmp(c->states[prev].digest,data,32))c->edges[prev][si]++;
    }
    for(unsigned ci=0;ci<c->ncontexts;ci++){
        attest_context *ctx=&c->contexts[ci];attest_state *s=&c->states[ctx->state];
        if(a0==ctx->address&&target==s->updater){
            if(n>sizeof ctx->data-ctx->length){c->failed=1;return;}
            if(n&&uc_mem_read(uc,a1,ctx->data+ctx->length,(size_t)n)){c->failed=1;return;}
            ctx->length+=(size_t)n;
        }else if(a1==ctx->address&&a0&&target!=s->updater){
            unsigned pi;for(pi=0;pi<64;pi++)if(!c->pending[pi].used)break;
            if(pi==64){c->failed=1;return;}
            attest_pending *p=&c->pending[pi];p->used=1;p->pc=pc+4;p->out=a0;p->state=ctx->state;
            attestation_custom_sha(s->iv,ctx->data,ctx->length,p->expected);
        }
    }
}
static int attest_capture_material(const attest_capture *c,attestation_material *m){
    if(c->failed)return -1;
    unsigned pairs=0;
    for(unsigned i=0;i<c->nstates;i++)for(unsigned j=0;j<c->nstates;j++)
        if(c->states[i].verified&&c->states[j].verified&&c->edges[i][j]&&
           c->states[i].updater==c->states[j].updater){
            memcpy(m->primary,c->states[i].iv,32);memcpy(m->secondary,c->states[j].iv,32);pairs++;
        }
    return pairs==1?0:-1;
}

static int attest_codec_image(const emu_t *e,const uint8_t *image,uint64_t *multiplier){
    uint64_t value=0;unsigned matches=0;
    for(int si=0;si<e->nsegs;si++){
        const seg_t *s=&e->segs[si];if(!(s->flags&1))continue;
        if(s->off>e->raw_len||s->filesz>e->raw_len-s->off)return -1;
        for(uint64_t j=0;j+36<=s->filesz;j+=4){
            const uint8_t *p=image+s->off+j;uint32_t mov=rd32(p,0),sub=rd32(p,4),load=rd32(p,8),pre=rd32(p,12),mul=rd32(p,20),store=rd32(p,24),dec=rd32(p,28),branch=rd32(p,32);
            if((mov&0xffe00000u)!=0x92800000u||(sub&0xffc00000u)!=0xd1000000u||
               ((sub>>10)&4095)!=8||(sub&31)!=((sub>>5)&31)||
               (load&0xffc00000u)!=0xf9400000u||((load>>10)&4095)!=0||
               ((load>>5)&31)!=(sub&31)||(pre&0xffe00c00u)!=0xf8400c00u||((pre>>12)&511)!=504||
               ((pre>>5)&31)!=(sub&31)||rd32(p,16)!=0xd503201fu||
               (mul&0xffe08000u)!=0x9b000000u||((mul>>16)&31)!=(mov&31)||
               (mul&31)!=((mul>>10)&31)||((mul>>5)&31)!=(pre&31)||(mul&31)!=(load&31)||
               (store&0xffe0fc00u)!=0xf8207800u||(store&31)!=(mul&31)||((store>>16)&31)!=(dec&31)||
               (dec&0xffc00000u)!=0xf1000000u||((dec>>10)&4095)!=1||(dec&31)!=((dec>>5)&31)||
               (branch&0xff00001fu)!=0x54000001u)continue;
            int32_t delta=(int32_t)((branch>>5)&0x7ffff);if(delta&0x40000)delta-=0x80000;
            if(delta!=-6)continue; /* back edge to the paired word loads */
            uint64_t candidate=((mov>>5)&65535)+1;
            if(candidate<2)continue;
            value=candidate;matches++;
        }
    }
    if(matches!=1)return -1;
    /* Require the corresponding forward recurrence too, with register dataflow. */
    unsigned forwards=0;
    for(int si=0;si<e->nsegs;si++){
        const seg_t *s=&e->segs[si];if(!(s->flags&1))continue;
        for(uint64_t j=0;j+28<=s->filesz;j+=4){
            const uint8_t *p=image+s->off+j;uint32_t mov=rd32(p,0);
            if((mov&0x7fe00000u)!=0x52800000u||((mov>>5)&65535)!=value)continue;
            for(unsigned k=4;k<=24;k+=4){uint32_t mul=rd32(p,k);
                if((mul&0xffe08000u)==0x9b000000u&&((mul>>16)&31)==(mov&31)&&
                   (mul&31)==((mul>>5)&31)&&(mul&31)!=((mul>>10)&31))forwards++;
            }
        }
    }
    if(forwards!=1)return -1;
    *multiplier=value;return 0;
}
static int attest_recover_codec(emu_t *e,uint64_t *multiplier){
    uint8_t *image=malloc(e->raw_len);if(!image)return -1;memcpy(image,e->raw,e->raw_len);
    int result=-1;
    for(int i=0;i<e->nsegs;i++){
        const seg_t *s=&e->segs[i];if(!(s->flags&1))continue;
        if(s->off>e->raw_len||s->filesz>e->raw_len-s->off||
           uc_mem_read(e->uc,e->load_bias+s->va,image+s->off,s->filesz))goto done;
    }
    result=attest_codec_image(e,image,multiplier);
done:free(image);return result;
}
#endif
