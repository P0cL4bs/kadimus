#ifndef KAD_STR
#define KAD_STR

#include <time.h>
#include <stdint.h>
#include <curl/curl.h>
#include "kadimus_mem.h"
#include "kadimus_common.h"

#define R_SIZE 20
#define M_ALL_SIZE (R_SIZE-1)*2+5
#define VULN_SIZE (R_SIZE-1)*2+11

struct parameter_list {
    size_t len;
    struct parameter *parameter;
    void *trash;
};

struct parameter {
    char *key;
    int key_size;
    char *value;
    int value_size;
};

struct dynptr {
    char *ptr;
    size_t len;
};

enum {
    replace_string,
    append_after,
    append_before
};

char *random_string(char *s, const size_t len);
void extract_url(const char *url, char **base_uri, char **parameters);
char *diff(const char *x, const char *y);
void trim_string(char **diff_str);
int b64decode(const char *encoded, struct dynptr *out);
char *b64encode(const char *data, int len);
int isb64valid(const char *encoded, size_t length);
void chomp_all(char *str);
char *cookie_append(const char *x, const char *y);
void build_regex(char regex[], char *r_str, char *middle);
char *make_code(const char *mark, const char *code, bool auth);
bool get_element_pos(struct parameter_list *plist, char **base, const char *url, const char *parameter, size_t *pos);
char *urlencode(const char *str);
char *build_url(const char *base, struct parameter_list *plist, int pos, const char *new, int action);
void tokenize(const char *parameters, struct parameter_list *plist);

#endif
