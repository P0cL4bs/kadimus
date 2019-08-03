#ifndef __BASE64_H__
#define __BASE64_H__

#include <stddef.h>

int isb64valid(const char *encoded, size_t length);

char *b64encode(const char *data, size_t len);
char *b64decode(const char *encoded, size_t *len);

#endif
