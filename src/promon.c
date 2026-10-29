#define _POSIX_C_SOURCE 200809L
#include "promon.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct source {
    char *relative, *name;
    char **lines; size_t nlines;
    int smali, native_class, registrar_class, field_class;
    long group;
};
struct sources { struct source *items; size_t count; };
struct stats { size_t groups, fields, resolvers, natives, registrations, libraries, reporters; };

static char *join(const char *a, const char *b){
    size_t n = strlen(a) + strlen(b) + 2;
    char *s = malloc(n);
    if(s) snprintf(s, n, "%s/%s", a, b);
    return s;
}
static const char *trim(const char *s){ while(*s == ' ' || *s == '\t' || *s == '\r') s++; return s; }
static int starts(const char *s, const char *p){ return !strncmp(trim(s), p, strlen(p)); }
static int token(const char *s, const char *word){
    size_t n = strlen(word);
    for(const char *p = s; (p = strstr(p, word)); p += n)
        if((p == s || p[-1] == ' ' || p[-1] == '\t') &&
           (!p[n] || p[n] == ' ' || p[n] == '\t')) return 1;
    return 0;
}
static char *descriptor(const char *line){
    const char *s = strchr(line, 'L'), *e = s ? strchr(s, ';') : NULL;
    return e ? strndup(s, (size_t)(e - s + 1)) : NULL;
}
static int load_lines(struct source *s, const char *path){
    FILE *f = fopen(path, "rb");
    if(!f) return -1;
    char *line = NULL; size_t cap = 0; ssize_t n;
    while((n = getline(&line, &cap, f)) >= 0){
        while(n && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = 0;
        char **p = realloc(s->lines, (s->nlines + 1) * sizeof *p);
        if(!p){ free(line); fclose(f); return -1; }
        s->lines = p;
        s->lines[s->nlines] = strdup(line);
        if(!s->lines[s->nlines]){ free(line); fclose(f); return -1; }
        s->nlines++;
        if(starts(line, ".class ")){ free(s->name); s->name = descriptor(line); }
    }
    free(line);
    int error = ferror(f); fclose(f);
    return error ? -1 : 0;
}
static int collect(struct sources *all, const char *root, const char *relative){
    char *path = *relative ? join(root, relative) : strdup(root);
    if(!path) return -1;
    DIR *d = opendir(path); free(path);
    if(!d) return -1;
    struct dirent *de; int rc = 0;
    while(!rc && (de = readdir(d))){
        if(!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char *rel = *relative ? join(relative, de->d_name) : strdup(de->d_name);
        char *full = rel ? join(root, rel) : NULL;
        struct stat st;
        if(!full || lstat(full, &st)){ free(rel); free(full); rc = -1; break; }
        if(S_ISDIR(st.st_mode)) rc = collect(all, root, rel);
        else if(S_ISREG(st.st_mode)){
            struct source *p = realloc(all->items, (all->count + 1) * sizeof *p);
            if(!p) rc = -1;
            else {
                all->items = p;
                struct source *s = &p[all->count++];
                memset(s, 0, sizeof *s); s->relative = rel; rel = NULL; s->group = -1;
                size_t n = strlen(s->relative);
                s->smali = n >= 6 && !strcmp(s->relative + n - 6, ".smali");
                if(s->smali) rc = load_lines(s, full);
            }
        } else { fprintf(stderr, "error: unsupported non-regular input: %s\n", full); rc = -1; }
        free(rel); free(full);
    }
    closedir(d); return rc;
}
static int field_decl(const char *line, char **name, char **type){
    if(!starts(line, ".field ")) return 0;
    const char *colon = strchr(line, ':');
    if(!colon) return 0;
    const char *start = colon;
    while(start > line && start[-1] != ' ' && start[-1] != '\t') start--;
    const char *end = colon + 1;
    while(*end && *end != ' ' && *end != '\t' && *end != '=') end++;
    *name = strndup(start, (size_t)(colon - start));
    *type = strndup(colon + 1, (size_t)(end - colon - 1));
    return *name && *type;
}
static const char *field_type(int type){ return type == 'S' ? "Ljava/lang/String;" : type == 'Z' ? "Z" : "I"; }
static size_t group_hits(const struct source *s, const struct promon_group *g){
    size_t hits = 0;
    for(size_t j = 0; j < g->count; j++){
        const struct promon_field *f = &g->fields[j];
        if(!strcmp(f->name, "LIBRARY_PACKAGE_NAME") && s->name && strstr(s->name, "/BuildConfig;") && f->type == 'S'){
            size_t n = strlen(s->name) - strlen("/BuildConfig;") - 1;
            if(n != f->text.len) return 0;
            for(size_t k = 0; k < n; k++)
                if((s->name[k+1] == '/' ? '.' : s->name[k+1]) != f->text.data[k]) return 0;
        }
        for(size_t k = 0; k < s->nlines; k++){
            char *name = NULL, *type = NULL;
            int match = field_decl(s->lines[k], &name, &type) &&
                        !strcmp(name, f->name) && !strcmp(type, field_type(f->type));
            free(name); free(type);
            if(match){ hits++; break; }
        }
    }
    return hits;
}
struct match { size_t source, group, hits, total; };
static int rank_match(const void *a, const void *b){
    const struct match *x = a, *y = b;
    int xe = x->hits == x->total, ye = y->hits == y->total;
    if(xe != ye) return ye - xe;
    if(x->hits != y->hits) return x->hits > y->hits ? -1 : 1;
    if(x->total != y->total) return x->total > y->total ? -1 : 1;
    if(x->source != y->source) return x->source < y->source ? -1 : 1;
    return x->group < y->group ? -1 : x->group != y->group;
}
static int map_groups(struct sources *all, const struct promon_config *c, struct stats *stats){
    struct match *matches = NULL; size_t count = 0;
    unsigned char *used = calloc(c->ngroups ? c->ngroups : 1, 1);
    if(!used) return -1;
    for(size_t i = 0; i < all->count; i++){
        struct source *s = &all->items[i];
        if(!s->smali || !s->name || !s->field_class) continue;
        for(size_t j = 0; j < c->ngroups; j++){
            size_t hits = group_hits(s, &c->groups[j]);
            if(!hits || hits!=c->groups[j].count) continue;
            struct match *p = realloc(matches, (count + 1) * sizeof *p);
            if(!p){ free(matches); free(used); return -1; }
            matches = p; matches[count++] = (struct match){ i, j, hits, c->groups[j].count };
        }
    }
    qsort(matches, count, sizeof *matches, rank_match);
    for(size_t i = 0; i < count; i++){
        struct match *m = &matches[i];
        if(all->items[m->source].group >= 0 || used[m->group]) continue;
        all->items[m->source].group = (long)m->group;
        used[m->group] = 1; stats->groups++;
    }
    free(matches); free(used); return 0;
}
static void quoted(FILE *f, struct promon_text text){
    fputc('"', f);
    for(size_t i = 0; i < text.len; i++){
        unsigned char ch = text.data[i];
        if(ch == '\\' || ch == '"'){ fputc('\\', f); fputc(ch, f); }
        else if(ch == '\n') fputs("\\n", f);
        else if(ch == '\r') fputs("\\r", f);
        else if(ch == '\t') fputs("\\t", f);
        else if(ch < 32 || ch == 127) fprintf(f, "\\u%04x", ch);
        else fputc(ch, f);
    }
    fputc('"', f);
}
static void without_native(FILE *f, const char *line){
    const char *p = strstr(line, "native ");
    if(p){ fwrite(line, 1, (size_t)(p - line), f); fputs(p + 7, f); }
    else fputs(line, f);
    fputc('\n', f);
}
static void resolver_body(FILE *f, const struct promon_config *c){
    fputs("    .locals 1\n    packed-switch p0, :promon_strings\n    const/4 v0, 0x0\n    return-object v0\n", f);
    for(size_t i = 0; i < c->nstrings; i++){
        fprintf(f, "    :promon_string_%zu\n    const-string/jumbo v0, ", i);
        quoted(f, c->strings[i]); fputs("\n    return-object v0\n", f);
    }
    fputs("    :promon_strings\n    .packed-switch 0x0\n", f);
    for(size_t i = 0; i < c->nstrings; i++) fprintf(f, "        :promon_string_%zu\n", i);
    fputs("    .end packed-switch\n", f);
}
static void native_body(FILE *f, const char *header, int return_true){
    const char *args = strchr(header, '('), *end = args ? strchr(args, ')') : NULL;
    const char *ret = end ? end + 1 : "V";
    if(args && !strncmp(args, "([B)[B", 6)) fprintf(f, "    .locals 0\n    return-object p%d\n", token(header, "static") ? 0 : 1);
    else if(*ret == 'V') fputs("    .locals 0\n    return-void\n", f);
    else if(*ret == 'J' || *ret == 'D') fputs("    .locals 2\n    const-wide/16 v0, 0x0\n    return-wide v0\n", f);
    else if(!strncmp(ret,"Ljava/lang/String;",18)) fputs("    .locals 1\n    const-string/jumbo v0, \"\"\n    return-object v0\n", f);
    else if(*ret == 'L' || *ret == '[') fputs("    .locals 1\n    const/4 v0, 0x0\n    return-object v0\n", f);
    else fprintf(f, "    .locals 1\n    const/4 v0, 0x%x\n    return v0\n", *ret == 'Z' && return_true ? 1 : 0);
}
static int registration(const char *line){
    return starts(line, "invoke-static") && strstr(line, "(Ljava/lang/Class;I)V") != NULL;
}
/* Older loaders construct their library name with a constant char[] rather
 * than const-string. Evaluate only the narrow constant operations, and only
 * recognize the exact shield name; never suppress an arbitrary library load. */
static int char_array_shield(const struct source *s,size_t begin,size_t end){
    long values[256]={0};unsigned char known[256]={0},filled[256]={0};
    uint16_t chars[256]={0};int array=-1,length=0,constructed=0;
    for(size_t i=begin;i<end;i++){
        const char *p=trim(s->lines[i]);int a,b,c;char literal[64];
        if((!strncmp(p,"const/",6)||!strncmp(p,"const ",6))&&
           sscanf(strchr(p,' ')+1,"v%d, %63s",&a,literal)==2&&a>=0&&a<256){
            char *tail;values[a]=strtol(literal,&tail,0);known[a]=!*tail;
        }else if(sscanf(p,"new-array v%d, v%d, [C",&a,&b)==2&&strstr(p,"[C")){
            if(a<0||a>=256||b<0||b>=256||!known[b]||values[b]<=0||values[b]>256)return 0;
            array=a;length=(int)values[b];
        }else if(sscanf(p,"xor-int/lit16 v%d, v%d, %63s",&a,&b,literal)==3){
            if(a<0||a>=256||b<0||b>=256||!known[b])return 0;
            char *tail;long value=strtol(literal,&tail,0);if(*tail)return 0;
            values[a]=values[b]^value;known[a]=1;
        }else if(sscanf(p,"int-to-char v%d, v%d",&a,&b)==2){
            if(a<0||a>=256||b<0||b>=256||!known[b])return 0;
            values[a]=(uint16_t)values[b];known[a]=1;
        }else if(sscanf(p,"aput-char v%d, v%d, v%d",&a,&b,&c)==3){
            if(a<0||a>=256||c<0||c>=256||b!=array||!known[a]||!known[c]||values[c]<0||values[c]>=length)return 0;
            chars[values[c]]=(uint16_t)values[a];filled[values[c]]=1;
        }else if(sscanf(p,"aget-char v%d, v%d, v%d",&a,&b,&c)==3){
            if(a<0||a>=256||c<0||c>=256||b!=array||!known[c]||values[c]<0||values[c]>=length||!filled[values[c]])return 0;
            values[a]=chars[values[c]];known[a]=1;
        }else if(strstr(p,"Ljava/lang/String;-><init>([C)V"))constructed=1;
    }
    const char *expected="supercell_brawlstars";
    if(!constructed||length!=(int)strlen(expected))return 0;
    for(int i=0;i<length;i++)if(!filled[i]||chars[i]!=(unsigned char)expected[i])return 0;
    return 1;
}
static int write_source(FILE *out, struct source *s, const struct promon_config *c,
                        const char *resolver, const struct sources *all, struct stats *stats){
    int is_resolver = s->name && !strcmp(s->name, resolver), return_true = 0;
    size_t pkglen = (size_t)(strrchr(resolver, '/') ? strrchr(resolver, '/') - resolver + 1 : 1);
    int own_package = s->name && !strncmp(s->name, resolver, pkglen);
    for(size_t i = 0; i < s->nlines; i++){
        if(strstr(s->lines[i], "Landroid/view/ViewTreeObserver$OnPreDrawListener;") || strstr(s->lines[i], "\"supercell_brawlstars\"")) return_true = 1;
    }
    char *load_reg = NULL;int encoded_shield=0;
    for(size_t i = 0; i < s->nlines; i++){
        const char *line = s->lines[i];
        if(starts(line, ".method ")){
            free(load_reg); load_reg = NULL;
            size_t end = i + 1;
            while(end < s->nlines && !starts(s->lines[end], ".end method")) end++;
            if(end == s->nlines){ free(load_reg); return -1; }
            encoded_shield=own_package&&char_array_shield(s,i+1,end);
            int native = token(line, "native");
            int string_method = is_resolver && native && token(line, "static") && strstr(line, "(I)Ljava/lang/String;");
            int clinit = is_resolver && strstr(line, "<clinit>()V");
            int reporter = 0;
            if(own_package) for(size_t k = i + 1; k < end; k++)
                if(strstr(s->lines[k], "Ljava/lang/Thread$UncaughtExceptionHandler;->uncaughtException")) reporter = 1;
            if(string_method || clinit || reporter || (native && (s->native_class || is_resolver))){
                without_native(out, line);
                if(string_method){ resolver_body(out, c); stats->resolvers++; }
                else if(clinit || reporter){ fputs("    .locals 0\n    return-void\n", out); stats->reporters += reporter; }
                else { native_body(out, line, return_true); stats->natives++; }
                fputs(".end method\n", out); i = end; continue;
            }
        }
        if(starts(line, ".field ") && token(line, "static") && s->group >= 0){
            char *name = NULL, *type = NULL;
            const struct promon_field *field = NULL;
            if(field_decl(line, &name, &type)){
                const struct promon_group *g = &c->groups[s->group];
                for(size_t k = 0; k < g->count; k++)
                    if(!strcmp(name, g->fields[k].name) && !strcmp(type, field_type(g->fields[k].type))){ field = &g->fields[k]; break; }
            }
            free(name); free(type);
            if(field){
                const char *eq = strchr(line, '='); size_t n = eq ? (size_t)(eq - line) : strlen(line);
                while(n && (line[n-1] == ' ' || line[n-1] == '\t')) n--;
                fwrite(line, 1, n, out); fputs(" = ", out);
                if(field->type == 'S') quoted(out, field->text);
                else if(field->type == 'Z') fputs(field->value ? "true" : "false", out);
                else fprintf(out, "%lld", (long long)field->value);
                fputc('\n', out); stats->fields++; continue;
            }
        }
        if(registration(line)){
            char *target = descriptor(line);
            int remove = 0;
            for(size_t k=0;target && k<all->count;k++)
                if(all->items[k].registrar_class && all->items[k].name && !strcmp(target,all->items[k].name)) remove=1;
            free(target);
            if(remove){ stats->registrations++; continue; }
        }
        if(starts(line, "const-string") && strstr(line, "\"supercell_brawlstars\"")){
            const char *p = strchr(trim(line), ' ');
            if(p){ p = trim(p); const char *comma = strchr(p, ',');
                if(comma){ free(load_reg); load_reg = strndup(p, (size_t)(comma - p)); }
            }
        }
        if((load_reg||encoded_shield) && starts(line, "invoke-static") && strstr(line, "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V")){
            const char *reg = strchr(line, '{');
            if(encoded_shield || (reg && !strncmp(trim(reg + 1), load_reg, strlen(load_reg)))){
                fputs("    nop\n", out); stats->libraries++; free(load_reg); load_reg = NULL; continue;
            }
        }
        fputs(line, out); fputc('\n', out);
    }
    free(load_reg); return ferror(out) ? -1 : 0;
}
static int mkdir_parents(const char *path){
    char *s = strdup(path);
    if(!s) return -1;
    for(char *p = s + 1; *p; p++) if(*p == '/'){
        *p = 0;
        if(mkdir(s, 0755) && errno != EEXIST){ free(s); return -1; }
        *p = '/';
    }
    free(s); return 0;
}
static void sources_free(struct sources *all){
    for(size_t i = 0; i < all->count; i++){
        struct source *s = &all->items[i];
        free(s->relative); free(s->name);
        for(size_t j = 0; j < s->nlines; j++) free(s->lines[j]);
        free(s->lines);
    }
    free(all->items);
}
void promon_config_free(struct promon_config *c){
    for(size_t i = 0; i < c->ngroups; i++){
        for(size_t j = 0; j < c->groups[i].count; j++) free(c->groups[i].fields[j].name);
        free(c->groups[i].fields);
    }
    free(c->groups); free(c->strings); memset(c, 0, sizeof *c);
}
int promon_patch(const char *input, const char *output, const struct promon_config *c){
    struct stat st;
    if(!c->nstrings || !stat(output, &st)){
        fprintf(stderr, "error: authenticated strings required; output must not already exist\n"); return -1;
    }
    struct sources all = {0}; struct stats stats = {0};
    char *resolver = NULL, *registrar = NULL; size_t resolvers = 0;
    if(collect(&all, input, "")) goto error;
    for(size_t i = 0; i < all.count; i++){
        struct source *s = &all.items[i];
        for(size_t j = 0; j < s->nlines; j++){
            const char *l = s->lines[j];
            if(starts(l, ".method ") && token(l, "native") && token(l, "static") && strstr(l, "(I)Ljava/lang/String;")){
                free(resolver); resolver = s->name ? strdup(s->name) : NULL; resolvers++;
            }
        }
    }
    if(resolvers != 1 || !resolver){ fprintf(stderr, "error: expected one native string resolver, found %zu\n", resolvers); goto error; }
    for(size_t i = 0; i < all.count; i++) if(all.items[i].name && !strcmp(all.items[i].name, resolver)){
        for(size_t j = 0; j < all.items[i].nlines; j++) if(registration(all.items[i].lines[j])){
            free(registrar); registrar = descriptor(all.items[i].lines[j]);
        }
        /* Earlier layouts put the native registrar directly on the string
         * resolver, without a self-registration call or class initializer. */
        if(!registrar) for(size_t j=0;j<all.items[i].nlines;j++){
            const char *line=all.items[i].lines[j];
            if(starts(line,".method ")&&token(line,"native")&&token(line,"static")&&
               strstr(line,"(Ljava/lang/Class;I)V"))registrar=strdup(resolver);
        }
    }
    if(!registrar){ fprintf(stderr, "error: cannot discover native registrar\n"); goto error; }
    for(size_t i = 0; i < all.count; i++) for(size_t j = 0; j < all.items[i].nlines; j++){
        if(!registration(all.items[i].lines[j])) continue;
        char *target = descriptor(all.items[i].lines[j]);
        if(target && !strcmp(target, registrar)) all.items[i].native_class = 1;
        free(target);
    }
    for(size_t i=0;i<all.count;i++){
        struct source *s=&all.items[i];
        if(!s->name || (!s->native_class && strcmp(s->name,registrar))) continue;
        for(size_t j=0;j<s->nlines;j++)
            if(starts(s->lines[j],".method ") && token(s->lines[j],"native") &&
               token(s->lines[j],"static") && strstr(s->lines[j],"(Ljava/lang/Class;I)V")) s->registrar_class=1;
    }
    for(size_t i=0;i<all.count;i++) for(size_t j=0;j<all.items[i].nlines;j++){
        if(!registration(all.items[i].lines[j])) continue;
        char *target=descriptor(all.items[i].lines[j]);
        for(size_t k=0;target && k<all.count;k++)
            if(all.items[k].registrar_class && all.items[k].name && !strcmp(target,all.items[k].name)) all.items[i].field_class=1;
        free(target);
    }
    if(map_groups(&all, c, &stats)) goto error;
    if(stats.groups != c->ngroups){
        fprintf(stderr, "error: matched only %zu/%zu field groups; refusing incomplete patch\n", stats.groups, c->ngroups); goto error;
    }
    if(mkdir_parents(output) || mkdir(output, 0755)) goto error;
    for(size_t i = 0; i < all.count; i++){
        struct source *s = &all.items[i]; char *path = join(output, s->relative);
        if(!path || mkdir_parents(path)){ free(path); goto error; }
        FILE *out = fopen(path, "wb"); free(path);
        if(!out) goto error;
        int rc = 0;
        if(s->smali) rc = write_source(out, s, c, resolver, &all, &stats);
        else {
            path = join(input, s->relative); FILE *in = path ? fopen(path, "rb") : NULL; free(path);
            if(!in) rc = -1;
            else { unsigned char buf[65536]; size_t n;
                while((n = fread(buf, 1, sizeof buf, in))) if(fwrite(buf, 1, n, out) != n){ rc = -1; break; }
                if(ferror(in)) rc = -1;
                fclose(in);
            }
        }
        if(fclose(out)) rc = -1;
        if(rc) goto error;
    }
    printf("Patched: %zu/%zu groups, %zu fields, %zu strings, %zu resolver, %zu native methods, %zu registrations, %zu protected loads, %zu crash reporters\n",
           stats.groups, c->ngroups, stats.fields, c->nstrings, stats.resolvers, stats.natives, stats.registrations, stats.libraries, stats.reporters);
    sources_free(&all); free(resolver); free(registrar); return 0;
error:
    sources_free(&all); free(resolver); free(registrar); return -1;
}
