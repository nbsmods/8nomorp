/* Recover and verify build material, then compute request tokens. */
#ifndef ATTEST_IMPL_H
#define ATTEST_IMPL_H
#include "attest_recover.h"

static int attest_bytes(const char *text,uint8_t *request,size_t length){
    if(strlen(text)!=length*2)return -1;
    for(size_t i=0;i<length;i++){
        unsigned value=0;
        for(unsigned j=0;j<2;j++){
            unsigned char c=(unsigned char)text[i*2+j];unsigned digit;
            if(c>='0'&&c<='9')digit=c-'0';
            else if(c>='a'&&c<='f')digit=c-'a'+10;
            else if(c>='A'&&c<='F')digit=c-'A'+10;
            else return -1;
            value=value*16+digit;
        }
        request[i]=(uint8_t)value;
    }
    return 0;
}
static int attest_hex(const char *text,uint8_t request[32]){return attest_bytes(text,request,32);}
static int attest_probe(emu_t *e,uint64_t function,const uint8_t request[32],uint8_t token[80]){
    uint64_t length=32,array=heap_alloc(e,40,1),response;
    if(!array||uc_mem_write(e->uc,array,&length,8)||uc_mem_write(e->uc,array+8,request,32)||
       native_jni_call(e,function,array,0))return -1;
    response=rdreg(e->uc,R_X0);
    if(!response||uc_mem_read(e->uc,response,&length,8)||length!=80)return -1;
    return uc_mem_read(e->uc,response+8,token,80)?-1:0;
}
static int attest_seed(const char *mode,const uint8_t request[32],uint64_t time,uint8_t seed[8]){
    if(!strcmp(mode,"random")){
        FILE *f=fopen("/dev/urandom","rb");if(!f)return -1;
        int result=fread(seed,1,8,f)==8?0:-1;fclose(f);return result;
    }
    if(strcmp(mode,"deterministic"))return attest_bytes(mode,seed,8);
    static const uint8_t domain[]="PepperAttestation.seed.v1";
    uint8_t bytes[8],digest[32];for(unsigned i=0;i<8;i++)bytes[i]=(uint8_t)(time>>(8*i));
    sha256_ctx ctx;sha256_init(&ctx);sha256_update(&ctx,domain,sizeof domain-1);
    sha256_update(&ctx,request,32);sha256_update(&ctx,bytes,8);sha256_final(&ctx,digest);memcpy(seed,digest,8);return 0;
}

int ctxgen_attest(const char *game_path,const char *shield_path,const char *apk_path,
                 const char *owner,uint32_t registration,const char *requests_path,
                 const char *time_text,const char *seed_mode,int verbose){
    emu_t *host=calloc(1,sizeof *host),*game=calloc(1,sizeof *game);
    FILE *requests=NULL;int result=-1;g_verbose=verbose;
    if(!host||!game)goto done;
    uint64_t client_time=0;uint8_t seed_check[8];
    if(strcmp(time_text,"auto")){
        char *end;errno=0;client_time=strtoull(time_text,&end,10);
        if(errno||!*time_text||*end||strspn(time_text,"0123456789")!=strlen(time_text))goto done;
    }
    if(strcmp(seed_mode,"random")&&strcmp(seed_mode,"deterministic")&&attest_bytes(seed_mode,seed_check,8))goto done;
    char line[68];unsigned count=0;uint8_t validated[32];
    if(requests_path){
        requests=fopen(requests_path,"r");if(!requests)goto done;
        while(fgets(line,sizeof line,requests)){
            line[strcspn(line,"\r\n")]=0;
            if(attest_hex(line,validated)||++count>65536){fprintf(stderr,"error: invalid request line\n");goto done;}
        }
        if(!count||!feof(requests)||ferror(requests)||fseek(requests,0,SEEK_SET))goto done;
    }
    native_probe_state_t probes;uint64_t function;
    if(native_load(host,shield_path,apk_path,game,game_path)||native_boot(host,game,&probes)||
       native_register(host,owner,registration,"([B)[B",&function)||!native_executable(host,function))goto done;
    fprintf(stderr,"[*] attestation callback %s at 0x%llx recovered from JNI registration\n",
            owner,(unsigned long long)function);
    host->strict_imports=1;
    attest_capture capture={0};capture.host=host;uc_hook capture_hook;
    uint8_t probe[32]={0},native_token[80];attestation_material material;
    if(uc_hook_add(host->uc,&capture_hook,UC_HOOK_CODE,attest_capture_code,&capture,1,0))goto done;
    int probe_result=attest_probe(host,function,probe,native_token);
    uc_hook_del(host->uc,capture_hook);
    if(probe_result||attest_capture_material(&capture,&material)||attest_recover_codec(host,&material.multiplier)){
        fprintf(stderr,"error: unsupported or unverified attestation material/codec\n");goto done;
    }
    for(unsigned i=0;i<sizeof probe;i++)probe[i]=(uint8_t)i;
    if(attest_probe(host,function,probe,native_token))goto done;
    for(unsigned i=0;i<4;i++){
        uint64_t decoded=rd64(native_token,(i+2)*8)-material.multiplier*rd64(native_token,(i+1)*8);
        uint64_t expected=rd64(probe,i*8)-(i?material.multiplier*rd64(probe,(i-1)*8):0);
        if(decoded!=expected){fprintf(stderr,"error: native request codec verification failed\n");goto done;}
    }
    fprintf(stderr,"[+] recovered SHA states verified against native digests; paired codec verified with a nonzero request\n");
    if(!requests){
        printf("{\"primary\":\"");for(unsigned i=0;i<32;i++)printf("%02x",material.primary[i]);
        printf("\",\"secondary\":\"");for(unsigned i=0;i<32;i++)printf("%02x",material.secondary[i]);
        printf("\",\"multiplier\":\"%llu\"}\n",(unsigned long long)material.multiplier);
        result=fflush(stdout)||ferror(stdout)?-1:0;goto done;
    }
    if(!strcmp(time_text,"auto"))client_time=(uint64_t)time(NULL);
    count=0;
    while(fgets(line,sizeof line,requests)){
        size_t length=strcspn(line,"\r\n");line[length]=0;
        uint8_t request[32],token[80],seed[8];
        if(attest_hex(line,request)||++count>65536){fprintf(stderr,"error: invalid request line\n");goto done;}
        if(attest_seed(seed_mode,request,client_time,seed)||attestation_compute(&material,request,client_time,seed,token))goto done;
        printf("{\"request\":\"");for(unsigned i=0;i<sizeof request;i++)printf("%02x",request[i]);
        printf("\",\"token\":\"");for(unsigned i=0;i<sizeof token;i++)printf("%02x",token[i]);
        printf("\",\"client_time\":\"%llu\",\"seed8\":\"",(unsigned long long)client_time);
        for(unsigned i=0;i<8;i++)printf("%02x",seed[i]);
        puts("\"}");
        if(fflush(stdout)||ferror(stdout))goto done;
    }
    if(!count||!feof(requests)||ferror(requests))goto done;
    result=0;
done:
    if(result)fprintf(stderr,"error: native attestation execution incomplete\n");
    if(requests)fclose(requests);
    if(game)game->uc=NULL;
    if(host){emu_free(host);native_free_image(host);}
    if(game)native_free_image(game);
    free(host);free(game);return result;
}
#endif
