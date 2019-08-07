#ifndef SPIDER_SOCKET_H
#define SPIDER_SOCKET_H

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <unistd.h>
#include <string.h>

#include "output.h"
#include "memory/alloc.h"

#define LISTEN_TIMEOUT 120

enum {
    SOCKS_SUCCESS,
    SOCKS_SEND_ERROR,
    SOCKS_RECV_ERROR,
    SOCKS_VERSION_ERROR,
    SOCKS_AUTH_REQUIRED,
    SOCKS_CON_ERROR,
    SOCKS_GETHOST_ERROR,
    SOCKS_TOTAL
};

int valid_ip_hostname(const char *hostname);
void start_listen(int *sock_fd, int port);
void start_bind_shell(int port);
void remote_connect(const char *con, int port, const char *proxy);

#endif
