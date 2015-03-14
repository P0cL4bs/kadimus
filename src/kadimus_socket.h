#ifndef SPIDER_SOCKET_H
#define SPIDER_SOCKET_H

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <unistd.h>

#include "kadimus_common.h"

int valid_ip_hostname(const char *hostname);
void start_listen(int *sock_fd, int port);
void reverse_shell(int port);
void bind_shell(const char *con, int port);

#endif

