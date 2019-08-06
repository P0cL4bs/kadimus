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

enum {
    replace_string,
    append_after,
    append_before
};

char *make_code(const char *mark, const char *code, bool auth);
char *build_url_simple(const char *url, const char *parameter, const char *newstring, int opt);
int parameter_exists(const char *url, const char *parameter);

#endif
