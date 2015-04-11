#include "kadimus_mem.h"

void *xmalloc(size_t len){
	void *ptr = malloc(len);

	if(ptr == NULL)
		die("malloc() error",1);

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
		die("xrealloc() error",1);

	return new_ptr;
}

char *xstrdup(const char *string){
	return strcpy(xmalloc ( strlen(string) + 1 ), string);
}
