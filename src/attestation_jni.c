/* Android bridge. The build generates this header from the ORIGINAL libraries. */
#include "attestation.h"
#include "attestation_material.h"
#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

static void fail(JNIEnv *env,const char *type,const char *message){
    jclass cls=(*env)->FindClass(env,type);
    if(cls)(*env)->ThrowNew(env,cls,message);
}
JNIEXPORT jbyteArray JNICALL Java_com_supercell_titan_AttestationBridge_compute(
        JNIEnv *env,jclass cls,jbyteArray input){
    (void)cls;uint8_t request[32],seed[8],token[80];
    if(!input||(*env)->GetArrayLength(env,input)!=32){
        fail(env,"java/lang/IllegalArgumentException","attestation request must be 32 bytes");return NULL;
    }
    (*env)->GetByteArrayRegion(env,input,0,32,(jbyte *)request);
    if((*env)->ExceptionCheck(env))return NULL;
    time_t now=time(NULL);
    if(now<0){fail(env,"java/lang/IllegalStateException","attestation clock unavailable");return NULL;}
    int fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC);size_t have=0;
    if(fd>=0){
        while(have<sizeof seed){
            ssize_t n=read(fd,seed+have,sizeof seed-have);
            if(n<0&&errno==EINTR)continue;
            if(n<=0)break;
            have+=(size_t)n;
        }
        close(fd);
    }
    if(have!=sizeof seed||attestation_compute(&build_material,request,(uint64_t)now,seed,token)){
        fail(env,"java/lang/IllegalStateException","attestation generation failed");return NULL;
    }
    jbyteArray output=(*env)->NewByteArray(env,sizeof token);
    if(output)(*env)->SetByteArrayRegion(env,output,0,sizeof token,(const jbyte *)token);
    return output;
}
