#include "string/concat.h"
#include "memory/alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *concatl(const char *str, ...)
{
	char *string = NULL;
	size_t size, len;
	va_list vl;

	va_start(vl, str);
	size = 0;

	do {
		len = strlen(str);
		xrealloc(string, string, (len + size + 1));
		memcpy(string + size, str, len);
		size += len;
	} while ((str = va_arg(vl, char *)));

	string[size] = 0x0;
	va_end(vl);

	return string;
}

// this function can cause a buffer-overflow
// use with caution
char *concatlb(char *buf, ...)
{
	char *str;
	size_t size, len;
	va_list vl;

	va_start(vl, buf);
	size = 0;

	while ((str = va_arg(vl, char *))) {
		len = strlen(str);
		memcpy(buf + size, str, len);
		size += len;
	}

	buf[size] = 0x0;
	va_end(vl);

	return buf;
}
