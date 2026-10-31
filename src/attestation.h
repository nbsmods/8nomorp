#ifndef ATTESTATION_H
#define ATTESTATION_H
#include <stdint.h>
#include <stddef.h>
typedef struct {
    uint8_t primary[32],secondary[32];
    uint64_t multiplier;
} attestation_material;
void attestation_custom_sha(const uint8_t state[32],const uint8_t *data,size_t length,uint8_t digest[32]);
int attestation_compute(const attestation_material *material,const uint8_t request[32],uint64_t client_time,
                        const uint8_t seed[8],uint8_t token[80]);
#endif
