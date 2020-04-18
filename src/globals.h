#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#include <stddef.h>

typedef struct {
	char *useragent;
	char *cookies;
	char *proxy;
	size_t timeout;
	size_t retry;
} globals_t;

extern globals_t global;

#endif
