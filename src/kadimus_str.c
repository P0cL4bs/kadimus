#include "kadimus_str.h"
#include "string/urlencode.h"
#include "string/base64.h"

void tokenize(const char *parameters, struct parameter_list *plist){
    struct parameter *aux;
    char *next, *prev;

    prev = strdup(parameters);
    plist->trash = prev;

    do {
        next = strchr(prev, '&');
        if(next){
            *next = 0x0;
            next++;
        }

        plist->parameter = realloc(plist->parameter, (plist->len+1)*sizeof(struct parameter));
        aux = plist->parameter+plist->len;
        aux->key = prev;
        if((aux->value = strchr(prev, '='))){
            *(aux->value) = 0x0;
            aux->value++;
            aux->value_size = strlen(aux->value);
        } else {
            aux->value_size = 0x0;
        }

        aux->key_size = strlen(aux->key);

        plist->len++;
    } while((prev = next));
}

char *random_string(char *s, const size_t len){
    static const char alphanum[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789";

    size_t i;

    if(!len)
        return s;

    for(i=0; i<len-1; i++){
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[i] = 0x0;

    return s;
}

void extract_url(const char *url, char **base_uri, char **parameters){
    size_t i = 0, end = 0, j = 0, len;
    if(!url)
        return;

    len = strlen(url);

    for(i=0; i<len; i++){
        if(url[i] == '?'){
            end = i;
            break;
        }
    }

    if(end == 0 || end == len-1)
        return;

    *base_uri = strncpy( xmalloc( end+1 ) , url, end );
    (*base_uri)[end] = 0x0;

    *parameters = xmalloc( len-end );

    end++;

    for(i=end, j = 0; i<len; i++, j++)
        (*parameters)[j] = url[i];

    (*parameters)[j] = 0x0;

}

char *diff(const char *x, const char *y){
    char *ret = NULL;
    int j = 0, i = 0, len_x = strlen(x), len_y = strlen(y),
    tmp = 0, tmp2 = 0, alloc_size = 0;


    if(len_x == 0 || len_y == 0)
        return NULL;
    //printf("len_x %d , len_y %d\n",len_x, len_y);

    for(i=0; x[i] && y[i] && x[i] == y[i]; i++);
    tmp = i;

    for(i=len_x-1 , j=len_y-1; j >= 0 && x[i] == y[j]; i--, j--);
    j++;
    tmp2 = j;

    if(tmp2 <= tmp)
        return NULL;

    alloc_size = 1+tmp2-tmp;

    ret = xmalloc( alloc_size );

    for( i=tmp, j=0; i < tmp2 ; i++, j++)
        ret[j] = y[i];
    ret[j] = 0x0;

    return ret;
}

void trim_string(char **diff_str){
    size_t i = 0, j = 0, start = 0, end = 0;
    char *aux = NULL;

    for(i=0; (*diff_str)[i]; i++)
        if((*diff_str)[i] != '\n' && (*diff_str)[i] != ' ' && (*diff_str)[i] != '\t')
            break;

    //if(! (*diff_str)[i] )
    //    return;

    start = i;

    for(i=start; (*diff_str)[i]; i++)
        if((*diff_str)[i] != '\n' && (*diff_str)[i] != ' ' && (*diff_str)[i] != '\t')
            break;

    end = i;

    if(end-start == 0)
        return;

    aux = xmalloc( 1+end-start );

    for(i=start, j=0; i < end; i++, j++)
        aux[j] = (*diff_str)[i];

    aux[j] = 0x0;
    xfree(diff_str);

    *diff_str = xstrdup(aux);

    xfree(aux);

    return;
}


void chomp_all(char *str){
    while(*str){
        if(*str == '\n')
            *str = ' ';
        str++;
    }
}

char *cookie_append(const char *x, const char *y){
    char *ret = NULL;
    size_t i,j;
    ret = xmalloc( strlen(x)+strlen(y)+2 );

    for(i=0, j=0; x[i]; i++, j++)
        ret[j] = x[i];

    ret[j] = '&';
    j++;

    for(i=0; y[i]; i++, j++)
        ret[j] = y[i];

    ret[j] = 0x0;

    return ret;
}

void build_regex(char regex[], char *r_str, char *middle){
    size_t i , j;

    for(i=0,j=0; r_str[i]; i++, j++)
        regex[j] = r_str[i];

    for(i=0; middle[i]; i++, j++)
        regex[j] = middle[i];

    for(i=0; r_str[i]; i++, j++)
        regex[j] = r_str[i];

    regex[j] = 0x0;


}

char *make_code(const char *mark, const char *code, bool auth){
    char *ret = NULL, *b64, *xpl_auth, *urlencoded;
    size_t len = 0, encode_auth_len;

    if(!auth){
        len = strlen(mark)*2+strlen(code)+2;
        ret = xmalloc( len );
        snprintf(ret, len, "%s%s%s",mark,code,mark);
    } else {
        ret = xmalloc( strlen(mark)*2+17*2+strlen(code)+2 );
        sprintf(ret, "<?php echo \"%s\"; ?>%s<?php echo \"%s\"; ?>", mark, code, mark);
        b64 = b64encode(ret, strlen(ret));
        urlencoded = urlencode(b64);
        xfree(b64);

        encode_auth_len = strlen(urlencoded)+18+1;

        xpl_auth = strcpy(xmalloc(encode_auth_len + 1), "stairway_to_heaven=");
        strcat(xpl_auth, urlencoded);

        xfree(urlencoded);
        xfree(ret);
        return xpl_auth;
    }

    return ret;
}

char *build_url(const char *base, struct parameter_list *plist, int pos, const char *new, int action){
    size_t baselen, newlen, total, i;
    int j;
    char *ret;

    total = baselen = strlen(base);
    newlen = strlen(new);

    total += newlen;

    for(i=0; i<plist->len; i++){
        total++;
        total += plist->parameter[i].key_size;
        if(plist->parameter[i].value_size){
            total++;

            if(i == (size_t)pos && action == replace_string)
                continue;

            total += plist->parameter[i].value_size;
        } else if(i == (size_t)pos) {
            total++;
        }
    }

    ret = malloc(total+1);
    memcpy(ret, base, baselen);
    ret[baselen] = '?';
    j = baselen;

    for(i=0; i<plist->len; i++){
        j++;

        memcpy(ret+j, plist->parameter[i].key, plist->parameter[i].key_size);
        j += plist->parameter[i].key_size;

        if(i == (size_t)pos){
            ret[j++] = '=';

            switch(action){
                case replace_string:
                    memcpy(ret+j, new, newlen);
                    j += newlen;
                break;
                case append_before:
                    memcpy(ret+j, new, newlen);
                    j += newlen;

                    memcpy(ret+j, plist->parameter[i].value, plist->parameter[i].value_size);
                    j += plist->parameter[i].value_size;
                break;
                case append_after:
                    memcpy(ret+j, plist->parameter[i].value, plist->parameter[i].value_size);
                    j += plist->parameter[i].value_size;

                    memcpy(ret+j, new, newlen);
                    j += newlen;
                break;
            }
        } else {
            if(plist->parameter[i].value){
                ret[j++] = '=';
                memcpy(ret+j, plist->parameter[i].value, plist->parameter[i].value_size);
                j += plist->parameter[i].value_size;
            }
        }

        ret[j] = '&';
    }

    ret[j] = 0x0;


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

    aux = ret = malloc(alloc+endlen+restlen+1);

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
