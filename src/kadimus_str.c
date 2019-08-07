#include "kadimus_str.h"
#include "string/urlencode.h"
#include "string/base64.h"
#include "string/utils.h"

char *make_code(const char *mark, const char *code, bool auth){
    char *ret = NULL, *b64, *xpl_auth, *urlencoded;
    size_t len = 0, encode_auth_len;

    if(!auth){
        len = strlen(mark)*2+strlen(code)+2;
        xmalloc(ret, len );
        snprintf(ret, len, "%s%s%s",mark,code,mark);
    } else {
        xmalloc(ret, strlen(mark)*2+17*2+strlen(code)+2 );
        sprintf(ret, "<?php echo \"%s\"; ?>%s<?php echo \"%s\"; ?>", mark, code, mark);
        b64 = b64encode(ret, strlen(ret));
        urlencoded = urlencode(b64);
        xfree(b64);

        encode_auth_len = strlen(urlencoded)+18+1;
        xmalloc(xpl_auth, encode_auth_len + 1);
        strcpy(xpl_auth, "stairway_to_heaven=");
        strcat(xpl_auth, urlencoded);

        xfree(urlencoded);
        xfree(ret);
        return xpl_auth;
    }

    return ret;
}

char *build_url_simple(const char *url, const char *parameter, const char *newstring, int opt){
    char *ret = NULL, *pstart, *urlend, *aux, *rest = NULL;
    size_t len, nlen, alloc, endlen, restlen = 0;

    if((pstart = strchr(url, '?')) == NULL)
        goto end;

    pstart++;
    if(!*pstart)
        goto end;

    len = strlen(parameter);
    if(!len)
        goto end;

    while(1){
        int status = strncmp(pstart, parameter, len);
        if(status || (pstart[len] != '&' && pstart[len] != '=' && pstart[len] != 0x0)){
            pstart = strchr(pstart, '&');
            if(!pstart)
                goto end;

            pstart++;
            continue;
        }

        urlend = strchr(pstart, '&');
        if(urlend){
            endlen = strlen(urlend);
            if(opt != replace_string ){
                rest = pstart+len;
                if(*rest == '=')
                    rest++;

                restlen = urlend-rest;
            }
        } else {
            endlen = 0;
        }

        break;
    }

    nlen = strlen(newstring);
    size_t basesize = pstart-url+len;
    alloc = basesize+1+nlen;

    xmalloc(ret, alloc+endlen+restlen+1);
    aux = ret;

    memcpy(aux, url, basesize);
    aux[basesize] = '=';
    aux += basesize+1;

    switch(opt){
        case replace_string:
            memcpy(aux, newstring, nlen);
            aux += nlen;
        break;
        case append_before:
            memcpy(aux, newstring, nlen);
            aux += nlen;

            memcpy(aux, rest, restlen);
            aux += restlen;
        break;
        case append_after:
            memcpy(aux, rest, restlen);
            aux += restlen;

            memcpy(aux, newstring, nlen);
            aux += nlen;
        break;
    }

    memcpy(aux, urlend, endlen);
    aux[endlen] = 0x0;

    end:
    return ret;
}

int parameter_exists(const char *url, const char *parameter){
    int ret = 0;
    char *pstart;
    size_t len;

    if(!url)
        goto end;

    if((pstart = strchr(url, '?')) == NULL)
        goto end;

    pstart++;
    if(!*pstart)
        goto end;

    len = strlen(parameter);
    while(1){
        int status = strncmp(pstart, parameter, len);
        if(status || (pstart[len] != '&' && pstart[len] != '=' && pstart[len] != 0x0)){
            pstart = strchr(pstart, '&');
            if(!pstart)
                goto end;

            pstart++;
        } else {
            ret = 1;
            break;
        }
    }

    end:
    return ret;
}
