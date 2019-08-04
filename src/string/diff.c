#include "diff.h"
#include "kadimus_mem.h"

#include <string.h>

char *diff(const char *string1, const char *string2){
    int i, j, len1, len2, size, aux;
    char *ret;

    len1 = strlen(string1);
    len2 = strlen(string2);

    if(!len1 && !len2){
        return NULL;
    }

    if(!len1){
        return xstrdup(string2);
    }

    for(i = 0; i < len1 && i < len2; i++){
        if(string1[i] != string2[i]){
            break;
        }
    }

    aux = i;

    for(i = len1 - 1, j = len2 - 1; i >= 0 && j >= 0; i--, j--){
        if(string1[i] != string2[j]){
            break;
        }
    }

    j++;

    if(j <= aux){
        return NULL;
    }

    size = j - aux;
    ret = xmalloc(size + 1);
    memcpy(ret, string2 + aux, size);
    ret[size] = 0x0;

    return ret;
}
