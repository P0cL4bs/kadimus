#ifndef __REQUEST_H__
#define __REQUEST_H__

#include <curl/curl.h>

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
int request_exec(request_t *request);
void request_free(request_t *request);

#endif
