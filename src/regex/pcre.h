#ifndef __REGEX_PCRE_H__
#define __REGEX_PCRE_H__

#include <pcre.h>

pcre *xpcre_compile(const char *pattern, int options);
char **regex_extract(int *len, const char *regex, const char *data, int size, int opts);
int regex_match(const char *regex, const char *data, int len, int opts);
int regex_matchv2(pcre *re, const char *data, int length, int opts);
void regex_free(char **match, int len);

#endif
