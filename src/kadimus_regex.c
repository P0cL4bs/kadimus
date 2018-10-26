#include "kadimus_regex.h"

char **regex_extract(const char *regex, const char *data, int size, int opts, int *len){
    pcre *re;
    int vet[VETSIZE] = {0}, errnb, i, j = 0, alloc, start, end, rc;

    const char *error;

    re = pcre_compile(regex, opts, &error, &errnb, NULL);
    if(!re)
        return NULL;

    rc = pcre_exec(re, NULL, data, size, 0, 0, vet, VETSIZE);

    if(rc <= 0){
        pcre_free(re);
        return NULL;
    }

    *len = rc;

    char **matches = xmalloc(rc * sizeof(char *));

    for(i=1;i<rc;i++){
        start = vet[i*2];
        end = vet[i*2+1];

        alloc = end-start;

        matches[j] = xmalloc(alloc+1);
        memcpy(matches[j], data+start, alloc);
        matches[j][alloc] = 0x0;
        j++;
    }

    matches[j] = NULL;

    pcre_free(re);

    return matches;
}

int regex_match(const char *regex, const char *data, int length, int opts){
    pcre *re;
    int rc = 0, vet[VETSIZE] = {0};

    re = xpcre_compile(regex, opts);
    rc = pcre_exec(re, NULL, data, (length) ? length : (int)strlen(data), 0, 0, vet, VETSIZE);
    pcre_free(re);

    return (rc >= 0) ? 1 : 0;
}

pcre *xpcre_compile(const char *pattern, int options){
    const char *error;
    int offset;
    pcre *re = pcre_compile(pattern, options, &error, &offset, NULL);
    if(!re)
        die(error, 0);

    return re;
}

int regex_match_v2(pcre *re, const char *data, int length, int opts){
    return (pcre_exec(re, NULL, data, length, 0, opts, NULL, 0) < 0);
}

void regex_free(char **regex_match){
    size_t i;

    for(i=0;regex_match[i]!=NULL;i++){
        xfree(regex_match[i]);
    }

    xfree(regex_match);
}
