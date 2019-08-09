#include "request/request.h"
#include "memory/alloc.h"
#include "globals.h"
#include "output.h"

#include <string.h>

size_t cbwrite(char *data, size_t size, size_t nmemb, body_t *body);

void request_init(request_t *request){
    CURL *curl;

    memset(request, 0x0, sizeof(request_t));

    curl = request->ch = curl_easy_init();
    if(!curl)
        die("curl_easy_init() error\n");

    curl_easy_setopt(curl, CURLOPT_USERAGENT, global.useragent);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, global.timeout);
    curl_easy_setopt(curl, CURLOPT_PROXY, global.proxy);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_COOKIE, global.cookies);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &(request->body));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cbwrite);

    xmalloc(request->body.ptr, 1);
}

int request_exec(request_t *request){
    CURLcode res;
    size_t i;

    for(i = 0; i <= global.retry; i++){
        res = curl_easy_perform(request->ch);

        if(res != CURLE_OK){
            xerror("request failed: %s\n", curl_easy_strerror(res));
            continue;
        }

        request->body.ptr[request->body.len] = 0x0;

        return 0;
    }

    return 1;
}

void request_free(request_t *request){
    curl_easy_cleanup(request->ch);
    free(request->body.ptr);
}

size_t cbwrite(char *data, size_t size, size_t nmemb, body_t *body){
    size_t newsize = body->len + size * nmemb;

    xrealloc(body->ptr, body->ptr, newsize + 1);
    memcpy(body->ptr + body->len, data, size * nmemb);
    body->len = newsize;

    return size * nmemb;
}
