#include "io/utils.h"
#include "output.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

FILE *xfopen(const char *file, const char *mode)
{
	FILE *fh;

	if ((fh = fopen(file, mode)) == NULL) {
		xdie("fopen(%s, \"%s\") failed, errno = %d\n", file, mode, errno);
	}

	return fh;
}

FILE *randomfile(char *filename, int retry)
{
	int i, fd;

	strcpy(filename, "/tmp/kadimus-XXXXXX");

	for (i = 0; i <= retry; i++) {
		if ((fd = mkstemp(filename)) != -1) {
			return fdopen(fd, "w");
		}
	}

	return NULL;
}


off_t getfdsize(int fd)
{
	struct stat s;

	if (fstat(fd, &s) == -1) {
		xdie("fstat() failed\n");
	}

	return s.st_size;
}

int openro(const char *name)
{
	int fd;

	if ((fd = open(name, O_RDONLY)) == -1) {
		xdie("open() failed\n");
	}

	return fd;
}

void ioredirect(struct pollfd pfd[2])
{
	char buf[1024];
	ssize_t n;

	int i, success = 1;

	while (success) {
		if (poll(pfd, 2, -1) == -1)
			break;

		for (i = 0; i < 2; i++) {
			if (pfd[i].revents & POLLIN) {
				n = read(pfd[i].fd, buf, sizeof(buf));
				if (n <= 0) {
					success = 0;
					break;
				}

				write(pfd[(i + 1) % 2].fd, buf, n);
			}
		}
	}
}
