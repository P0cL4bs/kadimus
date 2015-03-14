#ifndef KAD_IO
#define KAD_IO

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "kadimus_common.h"

FILE *xfopen(const char *file, const char *mode);
size_t get_max_len(FILE *fh);
int readline(FILE *fh, char *line, size_t len);
FILE *get_random_file(size_t retry, char tmp_name[]);
int get_file_size(int fd);
int readonly(const char *name);

#endif

