#ifndef KAD_REG
#define KAD_REG

#include <pcre.h>
#include "kadimus_mem.h"
#include "kadimus_common.h"

#define VETSIZE 30
#define URL_REGEX "^(https?://)?.+/.*\\?.+$"

char **regex_extract(const char *regex, const char *data, int size, int opts, int *len);
int regex_match(const char *regex, const char *data, int length, int opts);
void regex_free(char **regex_match);
pcre *xpcre_compile(const char *pattern, int options);
int regex_match_v2(pcre *re, const char *data, int length, int opts);

#endif
