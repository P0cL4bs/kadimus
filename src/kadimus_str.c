#include "kadimus_str.h"
#define b64pos(ch) (strchr(b64, ch)-b64)

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *b64encode(const char *data, int len){
    char ch[3], *ret = NULL, *aux;
    int i = 0, j = 0, pad;

    if(!len)
        goto end;

    aux = malloc(((len+2)/3)*4+1);

    while(i<len){
        ch[1] = ch[2] = 0;
        ch[0] = data[i++];

        if(i < len){
            ch[1] = data[i++];
            if(i < len){
                ch[2] = data[i++];
            }
        }

        aux[j] = b64[ch[0] >> 2];
        aux[j+1] = b64[(ch[0] & 3) << 4 | ch[1] >> 4];
        aux[j+2] = b64[(ch[1] & 0xf) << 2 | ch[2] >> 6];
        aux[j+3] = b64[ch[2] & 0x3f];

        j += 4;
    }

    pad = len%3;

    if(pad){
        aux[j-1] = '=';
        if(pad == 1)
            aux[j-2] = '=';
    }

    aux[j] = 0x0;
    ret = urlencode(aux);
    free(aux);

    end:
    return ret;
}

int b64decode(const char *encoded, struct dynptr *out){
    size_t i = 0, j = 0, length;

    length = strlen(encoded);
    if(!isb64valid(encoded, length))
        return 0;

    out->ptr = malloc((length*0.75)+1);

    while(i<length){
        out->ptr[j++] = b64pos(encoded[i]) << 2 | b64pos(encoded[i+1]) >> 4;

        if(encoded[i+2] == '=')
            break;

        out->ptr[j++] = b64pos(encoded[i+1]) << 4 | b64pos(encoded[i+2]) >> 2;

        if(encoded[i+3] == '=')
            break;

        out->ptr[j++] = b64pos(encoded[i+2]) << 6 | b64pos(encoded[i+3]);

        i += 4;
    }

    out->ptr[j] = 0x0;
    out->len = j;

    return 1;
}

int isb64valid(const char *encoded, size_t length){
    size_t i;
    int ret = 0;
    int pos;

    if(!length || length%4)
        goto end;

    for(i=0; i<length; i+=4){
        if(!(strchr(b64, encoded[i])) || !(strchr(b64, encoded[i+1]))){
            goto end;
        }

        if(length != i+4){
            if(!(strchr(b64, encoded[i+2])) || !(strchr(b64, encoded[i+3]))){
                goto end;
            }
        }
    }

    if(encoded[i-2] == '='){
        if(encoded[i-1] != '='){
            goto end;
        }

        /* check if the first 4 bits are set */
        pos = strchr(b64, encoded[i-3])-b64;

        if(pos & 0xf)
            goto end;

    } else if(encoded[i-1] == '='){
        pos = strchr(b64, encoded[i-2])-b64;
        if(pos & 3)
            goto end;
    }


    ret = 1;

    end:
    return ret;
}


static inline int isokay(const char ch){
    return ((ch >= 'a' && ch <= 'z') ||
        (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9'));
}

char *urlencode(const char *str){
    static const char hextable[]="0123456789abcdef";

    char *ret, ch;
    int i, j = 0;

    for(i=0; (ch = str[i]); i++){
        if(isokay(ch))
            j++;

        else
            j += 3;
    }

    ret = malloc(j+1);
    i = 0;

    while((ch = *str++)){
        if(isokay(ch)){
            ret[i++] = ch;
        } else {
            ret[i] = '%';
            ret[i+1] = hextable[((ch/16)%16)];
            ret[i+2] = hextable[ch%16];

            i+=3;
        }
    }

    ret[i] = 0x0;

    return ret;

}

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
    char *ret = NULL, *b64x=NULL, *xpl_auth;
    size_t len = 0, encode_auth_len;

    if(!auth){
        len = strlen(mark)*2+strlen(code)+2;
        ret = xmalloc( len );
        snprintf(ret, len, "%s%s%s",mark,code,mark);
    } else {
        ret = xmalloc( strlen(mark)*2+17*2+strlen(code)+2 );
        sprintf(ret, "<?php echo \"%s\"; ?>%s<?php echo \"%s\"; ?>", mark, code, mark);
        b64x = b64encode(ret, strlen(ret));

        //encode_auth_len  = strlen(lol);
        //encode_auth = urlencode(lol);

        encode_auth_len = strlen(b64x)+18+1;

        xpl_auth = strcpy( xmalloc( (encode_auth_len+1) ), "stairway_to_heaven=");
        strcat(xpl_auth, b64x);

        //xfree(encode_auth);
        xfree(ret);
        xfree(b64x);
        return xpl_auth;
    }

    return ret;
}

bool get_element_pos(struct parameter_list *plist, char **base, const char *url,
    const char *parameter, size_t *pos){
    char *parameters=NULL;
    size_t i;

    extract_url(url, base, &parameters);

    if(!*base || !parameters){
        xfree(*base);
        xfree(parameters);
        return false;
    }

    tokenize(parameters, plist);
    xfree(parameters);

    for(i=0; i<plist->len; i++){
        if(!strcmp(parameter, plist->parameter[i].key) &&
            plist->parameter[i].value){
            *pos = i;
            return true;
        }
    }

    xfree(*base);
    free(plist->trash);
    free(plist->parameter);

    return false;

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

int parameter_exist(const char *url, const char *parameter){
    
}

void hexdump(const char *ptr, size_t len){
    static const char hextable[]="0123456789abcdef";
    size_t i = 0, total;
    int offset, ch_offset;
    char hex[80], *aux, ch;
    unsigned int count = 0;

    while(i<len){
        offset = sprintf(hex, "0x%08x:  ", count);
        aux = hex+offset;
        ch_offset = 41;
        offset = 0;

        total = i+16;
        if(total > len)
            total = len;

        for(; i<total; i++){
            ch = ptr[i];
            aux[offset++] = hextable[ch/16];
            aux[offset++] = hextable[ch%16];
            aux[ch_offset++] = (ch > ' ' && ch <= '~') ? ch : '.';

            if(i%2)
                aux[offset++] = ' ';
        }

        aux[ch_offset] = 0x0;
        memset(aux+offset, ' ', 41-offset);

        puts(hex);
        count += 16;


        i = total;
    }
}
