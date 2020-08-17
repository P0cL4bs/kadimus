#include "net/utils.h"
#include "net/xconnect.h"
#include "net/listen.h"
#include "io/utils.h"
#include "output.h"

#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int listen_timeout = 120;

int checkhostname(const char *hostname)
{
	struct addrinfo *res, hints;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	if (getaddrinfo(hostname, NULL, &hints, &res)) {
		return 1;
	}

	freeaddrinfo(res);
	return 0;
}

void bindshell(uint16_t port)
{
	struct pollfd pfd[2];
	struct sockaddr_in addr;

	char ipstr[INET_ADDRSTRLEN];
	int fd, cli;
	pid_t pid;

	socklen_t slen = sizeof(struct sockaddr_in);
	fd = start_listen(port);

	pfd[0].fd = fd;
	pfd[0].events = POLLIN;

	pid = getpid();
	info("[pid: %d] listen on port: %d\n", pid, port);
	info("[pid: %d] waiting connection...\n", pid);

	switch (poll(pfd, 1, listen_timeout * 1000)) {
		case 0:
			error("[pid: %d] connection timeout %d !!!\n", pid, listen_timeout);
			exit(1);
		case -1:
			xdie("poll() failed\n");
	}

	if ((cli = accept(fd, (struct sockaddr *)&addr, &slen)) == -1) {
		xdie("accpet() failed\n");
	}

	inet_ntop(AF_INET, &addr.sin_addr, ipstr, INET_ADDRSTRLEN);

	good("[pid: %d] new connection from: %s\n", pid, ipstr);

	pfd[0].fd = cli;

	pfd[1].fd = 0;
	pfd[1].events = POLLIN;

	ioredirect(pfd);

	close(cli);
	close(fd);

	exit(0);
}

void remote_connect(const char *proxy, const char *target, uint16_t port)
{
	struct pollfd pfd[2];
	char *ip;
	int fd;

	if (proxy) {
		error("proxy support temporarily unavailable\n");
		return;
	}

	info("trying connect to %s:%d\n", target, port);
	if ((fd = xconnect(&ip, target, port)) == -1) {
		xdie("xconnect() failed\n");
	}

	good("connected in %s on port %d\n", ip, port);

	pfd[0].fd = fd;
	pfd[0].events = POLLIN;
	pfd[1].fd = 0;
	pfd[1].events = POLLIN;

	ioredirect(pfd);
}
