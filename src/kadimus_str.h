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
void trim_string(char **diff_str);
void chomp_all(char *str);
char *make_code(const char *mark, const char *code, bool auth);
char *build_url(const char *base, struct parameter_list *plist, int pos, const char *new, int action);
char *build_url_simple(const char *url, const char *parameter, const char *newstring, int opt);
int parameter_exists(const char *url, const char *parameter);
void tokenize(const char *parameters, struct parameter_list *plist);

#endif
