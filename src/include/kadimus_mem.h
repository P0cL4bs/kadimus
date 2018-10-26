#ifndef KAD_MEM
#define KAD_MEM

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "kadimus_common.h"

#define xfree(x) _xfree((void **)&x);

void *xmalloc(size_t len);
void _xfree(void **ptr);
void *xrealloc(void *ptr, size_t len);
char *xstrdup(const char *string);

#endif

