#include "string/url.h"
#include "string/utils.h"
#include "memory/alloc.h"
#include <string.h>

#define copyvalue(ptr, aux, value, size) do { \
	memcpy((ptr + (aux)), value, size); \
	aux += size; \
} while (0)

void urlparser(url_t *url, const char *string)
{
	char *aux, *nextkey, *key, *value;
	parameter_t *parameter;

	memset(url, 0x0, sizeof(url_t));

	aux = strchr(string, '?');
	if (aux) {
		url->base = xstrdupn(string, aux - string + 1);
	} else {
		url->base = xstrdup(string);
		return;
	}

	key = xstrdup(aux + 1);

	do {
		xrealloc(url->parameters, url->parameters,
			(url->plen + 1) * sizeof(parameter_t));
		parameter = url->parameters + url->plen;

		nextkey = strchr(key, '&');
		if (nextkey) {
			nextkey[0] = 0x0;
			nextkey++;
		}

		value = strchr(key, '=');
		if (value) {
			value[0] = 0x0;
			value++;
		}

		parameter->key = key;
		parameter->value = value;
		parameter->keysize = strlen(key);
		parameter->valuesize = (value ? strlen(value) : 0);

		url->plen++;
	} while ((key = nextkey));
}

void urlfree(url_t *url)
{
	free(url->base);
	if (url->parameters) {
		free(url->parameters->key);
		free(url->parameters);
	}
}

char *buildurl(url_t *url, int action, const char *newstr, int pos)
{
	parameter_t *parameter;
	char *ret;

	size_t len, j, nsize, basesize;
	int i;

	if (!url->plen) {
		return xstrdup(url->base);
	}

	nsize = strlen(newstr);
	basesize = strlen(url->base);
	len = 0;

	// calculate new string length
	for (i = 0; i < url->plen; i++) {
		parameter = url->parameters + i;

		len += parameter->keysize;
		if (pos == i) {
			// +1 for equal signal
			len += 1;
			len += nsize;

			if (action == string_replace) {
				continue;
			}
		} else {
			// +1 for equal signal
			if (parameter->value) {
				len += 1;
			}
		}

		if (parameter->value) {
			// +1 for equal signal
			len += parameter->valuesize;
		}
	}

	// len for '&' signal
	len += url->plen - 1;
	len += strlen(url->base);

	// write the new string
	xmalloc(ret, len + 1);

	memcpy(ret, url->base, basesize);
	j = basesize;

	for (i = 0; i < url->plen; i++) {
		parameter = url->parameters + i;

		copyvalue(ret, j, parameter->key, parameter->keysize);

		if (pos == i) {
			ret[j++] = '=';

			switch (action) {
				case string_replace:
					copyvalue(ret, j, newstr, nsize);
					break;
				case string_append:
					copyvalue(ret, j, parameter->value, parameter->valuesize);
					copyvalue(ret, j, newstr, nsize);
					break;
				case string_prepend:
					copyvalue(ret, j, newstr, nsize);
					copyvalue(ret, j, parameter->value, parameter->valuesize);
					break;
			}
		}

		else if (parameter->value) {
			ret[j++] = '=';
			copyvalue(ret, j, parameter->value, parameter->valuesize);
		}

		if ((i + 1) != url->plen) {
			ret[j++] = '&';
		}
	}

	ret[j] = 0x0;
	return ret;
}
