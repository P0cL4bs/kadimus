#ifndef __REQUEST_H__
#define __REQUEST_H__

#include <curl/curl.h>

#define request_resetbody(x) do { \
	free((x).body.ptr); \
	(x).body.ptr = NULL; \
	(x).body.len = 0; \
} while(0)

typedef struct {
	char *ptr;
	size_t len;
} body_t;

typedef struct {
	int status;
	char *filename;
	CURL *ch;
	body_t body;
	int finish;
} request_t;

void request_init(request_t *request);
void request_init_fh(request_t *request);
int request_exec(request_t *request);
void request_free(request_t *request);

#endif
