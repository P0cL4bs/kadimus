#include "regex/pcre.h"
#include "string/utils.h"
#include "memory/alloc.h"

pcre *xpcre_compile(const char *pattern, int options)
{
	const char *errptr;
	int offset;

	pcre *re = pcre_compile(pattern, options, &errptr, &offset, NULL);

	if (!re) {
		die("%s\n", errptr);
	}

	return re;
}

char **regex_extract(int *len, const char *regex, const char *data, int size, int opts)
{
	int vet[30], start, end, res, pos, i, rc;

	char **matches;

	pcre *re;

	re = xpcre_compile(regex, opts);

	rc = pcre_exec(re, NULL, data, size, 0, 0, vet, sizeof(vet) / sizeof(int));
	if (rc <= 0) {
		pcre_free(re);
		return NULL;
	}

	xmalloc(matches, rc * sizeof(char *));
	*len = rc - 1;
	pos = 0;

	for (i = 1; i < rc; i++) {
		start = vet[i * 2];
		end = vet[i * 2 + 1];

		res = end - start;

		matches[pos++] = xstrdupn(data + start, res);
	}

	pcre_free(re);
	return matches;
}

int regex_match(const char *regex, const char *data, int len, int opts)
{
	int rc, vet[3];
	pcre *re;

	if (!len) {
		len = strlen(data);
	}

	re = xpcre_compile(regex, opts);
	rc = pcre_exec(re, NULL, data, len, 0, 0, vet, 3);
	pcre_free(re);

	return (rc >= 0);
}

int regex_matchv2(pcre *re, const char *data, int length, int opts)
{
	return (pcre_exec(re, NULL, data, length, 0, opts, NULL, 0) < 0);
}

void regex_free(char **match, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		free(match[i]);
	}

	free(match);
}
