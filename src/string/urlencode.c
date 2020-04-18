#include "urlencode.h"
#include <stdlib.h>

static inline int isurlsafe(const char ch)
{
	return ((ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9'));
}

char *urlencode(const char *str)
{
	static const char hextable[]="0123456789abcdef";

	char *encoded_url, ch;
	int i, len = 0;

	for (i=0; (ch = str[i]); i++) {
		if (isurlsafe(ch)) {
			len++;
		} else {
			len += 3;
		}
	}

	if ((encoded_url = malloc(len + 1)) == NULL) {
		return NULL;
	}

	i = 0;
	while ((ch = *str++)) {
		if (isurlsafe(ch)) {
			encoded_url[i++] = ch;
		} else {
			encoded_url[i++] = '%';
			encoded_url[i++] = hextable[((ch/16)%16)];
			encoded_url[i++] = hextable[ch%16];
		}
	}

	encoded_url[i] = 0x0;

	return encoded_url;
}
