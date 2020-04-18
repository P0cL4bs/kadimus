#include "fun/http-shell.h"
#include "fun/exec-cmd.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void rce_http_shell(const char *url, const char *parameter, int technique)
{
	char *ptr = NULL;
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

		char *rce = exec_cmd(url, parameter, ptr, technique);
		if (rce) {
			printf("%s", rce);
			free(rce);
		}
	}

	free(ptr);
}
