#include "kadimus_regex.h"

char **regex_extract(const char *regex, const char *data, int size_data, int Options, int *len){
	pcre *re;
	//data_size = strlen(data)
	int vet[VET_SIZE] = {0},
	y = 0, j = 0, errornumber = 0, rc = 0, alloc = 0;
	*len = 0;
	int A = 0,B = 0;

	const char *error;

	re = pcre_compile(regex,Options,&error,&errornumber,NULL);
	if(!re) return NULL;
//die(error);

	rc = pcre_exec(re,NULL,data,(size_data) ? size_data : (int)strlen(data) ,0,0,vet,VET_SIZE);

	if(rc <= 0){
		pcre_free(re);
		return NULL;
	}

	*len = rc;

	char **matches = xmalloc(rc * sizeof(char *));
	int i = 0;

	for(i=1;i<rc;i++){
		A = i*2+1;
		B = A-1;

		alloc = vet[A]-vet[B];
		matches[(i-1)] = xmalloc( alloc+1 );

		for(j=vet[B],y=0; j<vet[A]; j++,y++)
			matches[(i-1)][y] = data[j];
		matches[(i-1)][y] = 0x0;
	}

	matches[rc-1] = NULL;

	pcre_free(re);

	return matches;

}

int regex_match(const char *regex, const char *data, int data_size, int Options){
	pcre *re;
	const char *error;
	int errornumber = 0, rc = 0, vet[VET_SIZE] = {0};

	re = pcre_compile(regex,Options,&error,&errornumber,NULL);
	if(!re) die(error,0);
	rc = pcre_exec(re,NULL,data,(data_size) ? data_size : (int)strlen(data),0,0,vet,VET_SIZE);
	pcre_free(re);

	return (rc >= 0) ? 1 : 0;

}

void regex_free(char **regex_match){
	size_t i;

	for(i=0;regex_match[i]!=NULL;i++){
		xfree(regex_match[i]);
	}

	xfree(regex_match);
}

