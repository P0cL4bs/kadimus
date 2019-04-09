#ifndef KAD_REQ
#define KAD_REQ

#include <curl/curl.h>
#include <stdbool.h>
#include <openssl/crypto.h>
#include <pthread.h>


#include "kadimus_mem.h"
#include "kadimus_common.h"

extern struct request_opts global;

struct request_opts {
    char *useragent;
    char *cookies;
    char *proxy;
    size_t timeout;
    size_t retry;
};

struct request {
    char *ptr;
    size_t len;
};

#define PROXY_REGEX "^.+:\\/\\/.+\\:(\\d+)$"

bool http_request(CURL *curl);
void init_str(struct request *x);
size_t writefunc(void *ptr, size_t size, size_t nmemb, struct request *s);
CURL *init_curl(void *ptr);

void init_locks(void);
void kill_locks(void);

#endif
