#include "kadimus_mem.h"

void *xmalloc(size_t len){
    void *ptr = malloc(len);

    if(ptr == NULL)
        xdie("malloc() failed\n");

    return ptr;
}

void _xfree(void **ptr){
    assert(ptr);
    if(ptr != NULL){
        free(*ptr);
        *ptr = NULL;
    }
}

void *xrealloc(void *ptr, size_t len){
    void *new_ptr = realloc(ptr, len);

    if(new_ptr == NULL)
        xdie("xrealloc() failed\n");

    return new_ptr;
}
