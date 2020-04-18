#include "net/listen.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int start_listen(uint16_t port)
{
	static struct sockaddr_in server_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = INADDR_ANY
	};

	int sockfd, enable = 1;

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd == -1) {
		return -1;
	}

	server_addr.sin_port = htons(port);

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		close(sockfd);
		return -1;
	}

	if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		close(sockfd);
		return -1;
	}

	listen(sockfd, SOMAXCONN);

	return sockfd;
}
