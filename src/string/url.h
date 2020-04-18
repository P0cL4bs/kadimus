#ifndef __URL_H__
#define __URL_H__

#include <stddef.h>

enum {
	string_replace,
	string_prepend,
	string_append
};

typedef struct {
	char *key;
	size_t keysize;
	char *value;
	size_t valuesize;
} parameter_t;

typedef struct {
	char *base;
	int plen;
	parameter_t *parameters;
} url_t;

void urlparser(url_t *url, const char *string);
void urlfree(url_t *url);

char *buildurl(url_t *url, int action, const char *newstr, int pos);

#endif
