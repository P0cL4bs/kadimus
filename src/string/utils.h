#ifndef __STRING_UTILS_H__
#define __STRING_UTILS_H__

#include <stddef.h>

char *xstrdup(const char *string);
char *xstrdupn(const char *str, size_t n);
char *trim(char **str);
char *randomstr(char *buf, int len);

#endif
