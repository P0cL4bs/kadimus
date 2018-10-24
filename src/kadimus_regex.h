#ifndef KAD_REG
#define KAD_REG

#include <pcre.h>
#include "kadimus_mem.h"
#include "kadimus_common.h"

#define VET_SIZE 30
#define URL_REGEX "^(https?://)?.+/.*\\?.+$"

char **regex_extract(const char *regex, const char *data, int size_data, int Options, int *len);
int regex_match(const char *regex, const char *data, int data_size, int Options);
void regex_free(char **regex_match);
pcre *xpcre_compile(const char *pattern, int options);
int regex_match_v2(pcre *re, const char *data, int length, int opts);

#endif
