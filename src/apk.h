#ifndef APK_H
#define APK_H
#include <stddef.h>
#include <stdint.h>
struct apk_metadata {
    char package[256],version[128];
    uint32_t version_code;
    struct { char name[256],permission[256]; } services[128];
    unsigned nservices;
    uint8_t *certificate;size_t certificate_len;
};
int apk_read_metadata(const uint8_t *data,size_t len,struct apk_metadata *out);
int apk_entry(const uint8_t *data,size_t len,const char *name,uint8_t **out,size_t *outlen);
void apk_metadata_free(struct apk_metadata *metadata);
#endif
