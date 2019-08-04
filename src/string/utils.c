#include "string/utils.h"
#include "kadimus_mem.h"
#include <string.h>

char *trim(char **str){
    char *aux;
    int len, i, start, end;

    aux = *str;
    len = strlen(aux);

    if(!len) goto end;

    for(i = 0; i < len; i++){
        if(aux[i] != ' ' && aux[i] != '\t' && aux[i] != '\n'){
            break;
        }
    }
    start = i;

    for(i = len - 1; i >= 0; i--){
        if(aux[i] != ' ' && aux[i] != '\t' && aux[i] != '\n'){
            break;
        }
    }
    end = i + 1;

    // the string has only space chars
    if(end < start){
        aux = xstrdup("");
        free(*str);
        *str = aux;
        goto end;
    }

    aux = xstrdupn(aux + start, end - start);
    free(*str);
    *str = aux;

    end:
    return *str;
}

char *xstrdupn(const char *str, size_t n){
    char *string;

    string = xmalloc(n + 1);
    memcpy(string, str, n);
    string[n] = 0x0;

    return string;
}

char *xstrdup(const char *string){
    size_t len = strlen(string);
    return xstrdupn(string, len);
}
