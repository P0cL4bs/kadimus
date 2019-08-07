#include "memory/alloc.h"
#include <stdlib.h>

void *_xmalloc(size_t len){
    if(len == 0)
        return NULL;

    return malloc(len);
}

void *_xrealloc(void *ptr, size_t len){
    if(ptr == NULL && len == 0)
        return NULL;

    return realloc(ptr, len);
}

void _xfree(void **ptr){
    if(ptr != NULL){
        free(*ptr);
        *ptr = NULL;
    }
}
