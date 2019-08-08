#ifndef __IO_UTILS_H__
#define __IO_UTILS_H__

#include <unistd.h>
#include <sys/poll.h>
#include <stdio.h>

FILE *xfopen(const char *file, const char *mode);
FILE *randomfile(char *filename, int retry);
off_t getfdsize(int fd);
int openro(const char *name);
void ioredirect(struct pollfd pfd[2]);

#endif
