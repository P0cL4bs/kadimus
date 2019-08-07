#ifndef __IO_UTILS_H__
#define __IO_UTILS_H__

#include "output.h"
#include <unistd.h>

FILE *xfopen(const char *file, const char *mode);
FILE *randomfile(char *filename, int retry);
off_t getfdsize(int fd);
int openro(const char *name);

#endif
