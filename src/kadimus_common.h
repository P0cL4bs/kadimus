#ifndef KAD_COM
#define KAD_COM

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define file_print(x...)\
	if(output)\
		fprintf(output, x);

#define print_single(x...)\
	if(!thread_on){\
		fprintf(stdout, x);\
		file_print(x);\
	}

#define print_thread(x...)\
	if(thread_on){\
		fprintf(stdout, x);\
		file_print(x);\
	}

#define print_all(x...)\
	fprintf(stdout, x);\
	file_print(x);

extern FILE *output;
extern bool thread_on;

void die(const char *err, int x);
//FILE *xfopen(const char *file, const char *mode);
void hex_print(const char *x);
//size_t get_max_len(FILE *fh);
//int readline(FILE *fh, char *line, size_t len);

#endif

