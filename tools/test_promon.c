#define _POSIX_C_SOURCE 200809L
#include "promon.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void put(const char *dir, const char *name, const char *text){
    char path[1024]; snprintf(path,sizeof path,"%s/%s",dir,name);
    FILE *f=fopen(path,"wb"); assert(f);
    assert(fputs(text,f)>=0); assert(!fclose(f));
}
static char *get(const char *dir, const char *name){
    char path[1024]; snprintf(path,sizeof path,"%s/%s",dir,name);
    FILE *f=fopen(path,"rb"); assert(f);
    assert(!fseek(f,0,SEEK_END)); long n=ftell(f); assert(n>=0);
    rewind(f); char *s=calloc((size_t)n+1,1); assert(s);
    assert(fread(s,1,(size_t)n,f)==(size_t)n); fclose(f); return s;
}
int main(void){
    char root[512];
    const char *tmp=getenv("TMPDIR");
    if(!tmp || !*tmp) tmp="/tmp";
    assert(snprintf(root,sizeof root,"%s/promon-test-XXXXXX",tmp)<(int)sizeof root);
    assert(mkdtemp(root));
    char in[1024],out[1024];
    snprintf(in,sizeof in,"%s/input",root); snprintf(out,sizeof out,"%s/output",root);
    assert(!mkdir(in,0755));
    put(in,"Resolver.smali",
        ".class public Lshield/Resolver;\n.super Ljava/lang/Object;\n"
        ".method static constructor <clinit>()V\n.locals 2\n"
        "invoke-static {v0,v1}, Lshield/Registrar;->a(Ljava/lang/Class;I)V\nreturn-void\n.end method\n"
        ".method public static native s(I)Ljava/lang/String;\n.end method\n");
    put(in,"Registrar.smali",
        ".class public Lshield/Registrar;\n.super Ljava/lang/Object;\n"
        ".method public static native a(Ljava/lang/Class;I)V\n.end method\n");
    put(in,"App.smali",
        ".class public Lapp/Example;\n.super Ljava/lang/Object;\n.field public static answer:I\n"
        ".method static constructor <clinit>()V\n.locals 2\n"
        "invoke-static {v0,v1}, Lshield/Registrar;->a(Ljava/lang/Class;I)V\n"
        "invoke-static {v0,v1}, Lapp/Other;->a(Ljava/lang/Class;I)V\nreturn-void\n.end method\n"
        ".method public native flag()Z\n.end method\n"
        ".method public native echo([B)[B\n.end method\n");
    put(in,"Real.smali",
        ".class public Lapp/RealNative;\n.super Ljava/lang/Object;\n"
        ".method public native untouched()J\n.end method\n");
    put(in,"asset.txt","unchanged\n");
    const uint8_t value[]="actual \"value\"\n";
    struct promon_text strings[]={{value,sizeof value-1}};
    struct promon_field fields[]={{"answer",'I',42,{NULL,0}}};
    struct promon_group groups[]={{fields,1}};
    struct promon_config c={strings,1,groups,1};
    assert(!promon_patch(in,out,&c));
    char *s=get(out,"Resolver.smali");
    assert(strstr(s,".packed-switch 0x0"));
    assert(strstr(s,"actual \\\"value\\\"\\n"));
    assert(!strstr(s,"native s(")); free(s);
    s=get(out,"App.smali");
    assert(strstr(s,"answer:I = 42"));
    assert(strstr(s,"return-object p1"));
    assert(!strstr(s,"Lshield/Registrar;->"));
    assert(strstr(s,"Lapp/Other;->")); free(s);
    s=get(out,"Real.smali"); assert(strstr(s,"native untouched")); free(s);
    s=get(out,"asset.txt"); assert(!strcmp(s,"unchanged\n")); free(s);
    s=get(in,"App.smali"); assert(strstr(s,"native flag")); free(s);
    assert(promon_patch(in,out,&c)<0);
    /* A renamed/missing field in a future layout must fail before output is
     * created, rather than silently emit a partially patched tree. */
    char rejected[1024];
    snprintf(rejected,sizeof rejected,"%s/rejected",root);
    struct promon_field unknown_fields[]={{"new_layout_field",'I',42,{NULL,0}}};
    struct promon_group unknown_groups[]={{unknown_fields,1}};
    struct promon_config unknown={strings,1,unknown_groups,1};
    assert(promon_patch(in,rejected,&unknown)<0);
    assert(access(rejected,F_OK)<0);
    s=get(in,"App.smali"); assert(strstr(s,"native flag")); free(s);
    puts("PASS: actual strings, fields, registrar scope, native passthrough, asset copy, no input overwrite, unknown-layout refusal");
    return 0;
}
