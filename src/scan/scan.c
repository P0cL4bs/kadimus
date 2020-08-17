#include "scan/scan.h"
#include "scan/rce-scan.h"
#include "request/request.h"
#include "string/utils.h"
#include "regex/pcre.h"
#include "io/utils.h"
#include "output.h"
#include "string/hexdump.h"
#include "string/base64.h"
#include "techniques/php-filter.h"
#include "memory/alloc.h"

#include <stdio.h>

int phpfilter_scan(scan_t *info, url_t *url, int pos)
{
	char *b64, *decoded;

	int success = 0;
	size_t len;

	b64 = phpfilter(url, info->origurl, url->parameters[pos].value, pos);

	if (!b64) {
		return 0;
	}

	if (thread_enable) {
		success = isb64valid(b64, strlen(b64));
		goto end;
	}

	if ((decoded = b64decode(b64, &len))) {
		success = 1;

		good("target probably vulnerable, hexdump: \n\n");
		hexdump(decoded, len, 0);
		print_all("\n");

		free(decoded);
	}

end:
	free(b64);
	return success;
}

void check_file_list(scan_t *info, url_t *url, int pos)
{
	FILE *fh;
	line_t line;
	request_t req;

	// suppress compile warning
	(void) info;

	char *filename, *regex, *target;

	memset(&line, 0x0, sizeof(line_t));
	fh = xfopen("./resource/common_files.txt", "r");

	request_init(&req);

	foreach (line, fh) {
		if (line.nread < 3 || line.buf[0] == '#' || line.buf[0] == ':') {
			continue;
		}

		if (line.buf[line.nread - 1] == '\n') {
			line.buf[line.nread - 1] = 0x0;
		}

		filename = line.buf;
		regex = strchr(line.buf, ':');

		if (regex == NULL) {
			continue;
		}

		regex[0] = 0x0;
		regex++;

		if (regex[0] == 0x0) {
			continue;
		}

		target = buildurl(url, string_replace, filename, pos);
		xinfo("requesting: %s\n", target);

		curl_easy_setopt(req.ch, CURLOPT_URL, target);
		if (request_exec(&req)) {
			xerror("no connection with the target URL, exiting...\n");
		}

		else {
			if (regex_match(regex, req.body.ptr, req.body.len, 0)) {
				xgood("regex match: %s\n", regex);
				xgood("check the URL: %s\n", target);
			}
		}

		free(target);

		xrealloc(req.body.ptr, req.body.ptr, 1);
		req.body.len = 0;
	}

	request_free(&req);
	fclose(fh);
}

int lfi_error_check(scan_t *scan, const char *target)
{
	request_t req;
	line_t line;
	int res;

	(void)scan;

	memset(&line, 0x0, sizeof(line_t));

	request_init(&req);
	curl_easy_setopt(req.ch, CURLOPT_URL, target);

	if (request_exec(&req)) {
		res = -1;
		goto end;
	}

	FILE *fh = xfopen("./resource/errors.txt", "r");
	res = 0;

	foreach (line, fh) {
		if (line.nread <= 1)
			continue;

		if (line.buf[line.nread - 1] == '\n') {
			line.buf[line.nread - 1] = 0x0;
		}

		if (regex_match(line.buf, req.body.ptr, req.body.len, 0)) {
			xgood("regex match: ( %s )\n", line.buf);
			res = 1;
			break;
		}
	}

	fclose(fh);

end:
	request_free(&req);
	free(line.buf);

	return res;
}

int isdynamic(scan_t *scan, const char *target)
{
	request_t req1, req2;
	int result;

	request_init(&req1);
	request_init(&req2);

	curl_easy_setopt(req1.ch, CURLOPT_URL, target);
	curl_easy_setopt(req2.ch, CURLOPT_URL, target);

	if (request_exec(&req1) || request_exec(&req2)) {
		result = -1;
		goto end;
	}

	if (req1.body.len == req2.body.len) {
		result = (memcmp(req1.body.ptr, req2.body.ptr, req1.body.len) != 0);
	} else {
		scan->dynamic = 1;
		result = 1;
	}

end:
	request_free(&req1);
	request_free(&req2);

	return result;
}

void kadimus_scan(const char *target)
{
	scan_t scan;

	parameter_t *parameter;
	url_t url;

	char *targeturl, rbuf[8];

	scan.origurl = (char *)target;
	scan.skip_nullbyte = 0;
	scan.skip_error_check = 0;
	scan.dynamic = 0;
	scan.dirback = -1;
	scan.skip_file_scan = 0;
	scan.skip_rce_scan = 0;

	urlparser(&url, target);

	info("scanning URL: %s\n", target);
	info("testing if URL has dynamic content...\n");

	switch (isdynamic(&scan, target)) {
		case 1:
			warn("URL has dynamic content\n");
			warn("skipping source disclosure test\n");
			break;
		case 0:
			info("URL doesn't have dynamic content\n");
			break;
		case -1:
			error("no connection with the target URL, exiting...\n");
			exit(1);
	}

	for (int i = 0; i < url.plen; i++) {
		parameter = url.parameters + i;
		if (!parameter->key[0]) {
			continue;
		}

		info("analyzing '%s' parameter...\n", parameter->key);
		if (!scan.skip_error_check) {
			info("checking for LFI error messages\n");

			targeturl = buildurl(&url, string_replace, randomstr(rbuf, sizeof(rbuf)) ,i);
			info("using random URL: %s\n", targeturl);

			switch (lfi_error_check(&scan, targeturl)) {
				case 1:
					info("LFI error found!\n");
					break;
				case 0:
					warn("LFI error not found\n");
					break;
				case -1:
					error("no connection with the target URL, exiting...\n");
					exit(1);
			}

			free(targeturl);
		}

		if (!scan.dynamic) {
			info("starting source disclosure test...\n");

			switch (phpfilter_scan(&scan, &url, i)) {
				case 0:
					warn("parameter doesn't seem to be vulnerable to source disclosure\n");
					break;

				case -1:
					error("no connection with the target URL, exiting...\n");
					exit(1);
					break;
			}
		}

		if (!scan.skip_file_scan) {
			info("checking common files...\n");
			check_file_list(&scan, &url, i);
			info("common files scan finished\n");
		}

		if (!scan.skip_rce_scan) {
			info("checking RCE...\n");
			kadimus_rce_scan(&url, i);
			info("RCE scan finished\n");
		}
	}

	urlfree(&url);
}
