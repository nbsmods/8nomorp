#ifndef PROMON_H
#define PROMON_H
#include <stddef.h>
#include <stdint.h>

struct promon_text { const uint8_t *data; size_t len; };
struct promon_field {
    char *name;
    int type;
    int64_t value;
    struct promon_text text;
};
struct promon_group { struct promon_field *fields; size_t count; };
struct promon_config {
    struct promon_text *strings; size_t nstrings;
    struct promon_group *groups; size_t ngroups;
};
/* Patch a decoded APK/smali tree into a new output directory. */
int promon_patch(const char *input, const char *output, const struct promon_config *config);
void promon_config_free(struct promon_config *config);
#endif
