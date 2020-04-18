#ifndef __IO_UTILS_H__
#define __IO_UTILS_H__

#include <unistd.h>
#include <sys/poll.h>
#include <stdio.h>

#define foreach(line, fh) while (((line).nread = \
	getline(&(line).buf, &(line).len, fh)) != -1)

typedef struct {
	ssize_t nread;
	size_t len;
	char *buf;
} line_t;

FILE *xfopen(const char *file, const char *mode);
FILE *randomfile(char *filename, int retry);
off_t getfdsize(int fd);
int openro(const char *name);
void ioredirect(struct pollfd pfd[2]);

#endif
