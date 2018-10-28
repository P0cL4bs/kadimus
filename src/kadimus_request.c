#include "kadimus_request.h"

struct request_opts global;

bool HttpRequest(CURL *curl){
    CURLcode res;
    size_t i;

    for(i=0; i<=global.retry; i++){
        res = curl_easy_perform(curl);

        if(res != CURLE_OK){
            error_single("request failed: %s\n", curl_easy_strerror(res));
            continue;
        }

        return true;
    }

    return false;

}

void init_str(struct request *x){
    x->len = 0;
    x->ptr = xmalloc(1);
    x->ptr[0] = 0x0;
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct request *s){
    size_t new_len = s->len + size*nmemb;

    s->ptr = xrealloc(s->ptr, new_len+1);

    memcpy(s->ptr+s->len, ptr, size*nmemb);
    s->ptr[new_len] = 0x0;
    s->len = new_len;

    return size*nmemb;
}

CURL *init_curl(void *ptr){
    CURL *curl = curl_easy_init();

    if(!curl)
        die("curl_easy_init() error",0);


    if(ptr){
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, ptr);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, (curl_write_callback) writefunc);
    }

    curl_easy_setopt(curl, CURLOPT_USERAGENT, global.useragent);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, global.timeout);
    curl_easy_setopt(curl, CURLOPT_PROXY, global.proxy);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_COOKIE, global.cookies);

    return curl;
}

static pthread_mutex_t *lockarray;

void lock_callback(int mode, int type, char *file, int line){
    (void)file;
    (void)line;

    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(lockarray[type]));
    }

    else {
        pthread_mutex_unlock(&(lockarray[type]));
    }

}

unsigned long thread_id(void){
    unsigned long ret;
    ret=(unsigned long)pthread_self();
    return(ret);
}

void init_locks(void){
    int i;

    lockarray=(pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));

    for (i=0; i<CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&(lockarray[i]),NULL);
    }

    CRYPTO_set_id_callback(thread_id);
    CRYPTO_set_locking_callback(lock_callback);
}

void kill_locks(void){
    int i;

    CRYPTO_set_locking_callback(NULL);
    for (i=0; i<CRYPTO_num_locks(); i++)
        pthread_mutex_destroy(&(lockarray[i]));

    OPENSSL_free(lockarray);
}
