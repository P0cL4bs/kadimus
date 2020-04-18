#ifndef __ALLOC_H__
#define __ALLOC_H__

#include "output.h"

#define xmalloc(ptr, len) do { \
	if ((ptr = _xmalloc(len)) == NULL) { \
		xdie("xmalloc(%u) failed, errno = %d\n", (unsigned int)(len), errno); \
	} \
} while (0)

#define xrealloc(ptr, old, len) do { \
	ptr = _xrealloc(old, len); \
	if (ptr == NULL) { \
		xdie("xrealloc(%p, %u) failed, errno = %d\n", old, (unsigned int)(len), errno); \
	} \
} while (0)

#define xfree(x) _xfree((void **)&x)

void *_xmalloc(size_t len);
void *_xrealloc(void *ptr, size_t len);
void _xfree(void **ptr);

#endif
