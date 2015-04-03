#include "kadimus_socket.h"

int valid_ip_hostname(const char *hostname){
	struct addrinfo *servinfo, hints;
	int rv;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	if( (rv = getaddrinfo(hostname, NULL, &hints, &servinfo)) != 0){
		fprintf(stderr, "[-] getaddrinfo(%s) : %s\n", hostname, gai_strerror(rv));
		exit(1);
	}
	freeaddrinfo(servinfo);
	return 1;
}

int kadimus_connect(const char *hostname, unsigned short port, char **ip){
	struct addrinfo hints, *servinfo, *i;
	int status = 0, sockfd = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	if( (status = getaddrinfo(hostname, NULL, &hints, &servinfo)) != 0){
		fprintf(stderr, "[-] getaddrinfo: %s\n", gai_strerror(status));
		exit(1);
	}

	for(i=servinfo; i != NULL; i = i->ai_next){
		if((sockfd = socket(i->ai_family, i->ai_socktype, i->ai_protocol)) == -1)
			continue;

		((struct sockaddr_in *)i->ai_addr)->sin_port = htons(port);

		if( connect(sockfd, i->ai_addr, i->ai_addrlen) == -1){
			close(sockfd);
			continue;
		}

		break;
	}

	if(i){
		if(ip != NULL){
			*ip = xmalloc(INET_ADDRSTRLEN);
			if(i->ai_family == AF_INET){
				inet_ntop(AF_INET, &((struct sockaddr_in *)(i->ai_addr))->sin_addr, *ip, INET_ADDRSTRLEN);
			}

			else if(i->ai_family == AF_INET6){
				inet_ntop(AF_INET6, &((struct sockaddr_in6 *)(i->ai_addr))->sin6_addr, *ip, INET6_ADDRSTRLEN);
			}

		}

		freeaddrinfo(servinfo);
	}

	else {
		freeaddrinfo(servinfo);
		return -1;
	}

	return sockfd;

}

void start_listen(int *sock_fd, int port){
	struct sockaddr_in server_addr;
	int optval = 1;

	if( (*sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		die("socket() error",1);

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	bzero(&(server_addr.sin_zero), 8);

	if(setsockopt(*sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval) == -1)
		die("setsockopt() error",1);

	if(bind(*sock_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
		die("bind() error",1);

	if(listen(*sock_fd,1) == -1)
		die("listen() error",1);

}

void reverse_shell(int port){
	int sock, i, ret, sock_con = 0;
	struct sockaddr cli_addr;
	struct pollfd pfds[2];
	struct timeval timeout;
	char ip_connection[INET6_ADDRSTRLEN] = {0};
	char buf[1024];
	fd_set fd;

	socklen_t sockaddr_len = sizeof(struct sockaddr_in);
	start_listen(&sock, port);

	FD_ZERO(&fd);
	FD_SET(sock, &fd);

	printf("Listen in background, port: %d, pid: %lld\nWaiting connection ...\n", port, (long long int) getpid());

	timeout.tv_sec = LISTEN_TIMEOUT;
	timeout.tv_usec = 0;
	ret = select(sock+1, &fd, NULL, NULL, &timeout);

	if(ret == -1)
		die("select() error",1);
	else if(!ret){
		printf("Connection timeout %d !!!\n",LISTEN_TIMEOUT);
		exit(0);
	}

	if( (sock_con = accept(sock, (struct sockaddr *) &cli_addr, &sockaddr_len)) == -1 )
		die("accept() error",1);

	if(cli_addr.sa_family == AF_INET){
		inet_ntop(AF_INET, &((struct sockaddr_in *)&cli_addr)->sin_addr, ip_connection, INET_ADDRSTRLEN);
	} else if(cli_addr.sa_family == AF_INET6){
		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&cli_addr)->sin6_addr), ip_connection, INET6_ADDRSTRLEN);
	} else {
		strcpy(ip_connection, "unknow");
	}

	printf("Connection from: %s\n\n", ip_connection);

	pfds[1].fd = 0;
	pfds[1].events = POLLIN;
	pfds[0].fd = sock_con;
	pfds[0].events = POLLIN;

	while(1){
		poll(pfds, 2, -1);

		if(pfds[1].revents & POLLIN){
			i = read(0, buf, 1023);

			if(!i)
				break;

			write(sock_con, buf, i);

		}

		if(pfds[0].revents & POLLIN){
			i = read(sock_con, buf, 1023);
			if(!i)
				break;

			write(1, buf, i);
		}

	}

	exit(0);
}

int socks5_connection(int proxyfd, const char *host, unsigned short port){
	char hello[]={ 0x5, 0x1, 0x0 };
	char step_two[256]={ 0x5, 0x1, 0x0, 0x1 };
	char recvbuffer[256];
	struct sockaddr_in addr;
	struct hostent *hostx;


	if( (hostx = gethostbyname(host)) == NULL)
		return SOCKS_GETHOST_ERROR;

	if( send(proxyfd, hello, sizeof(hello), 0) != sizeof(hello) )
		return SOCKS_SEND_ERROR;

	if( recv(proxyfd, recvbuffer, 256, 0) < 2 )
		return SOCKS_RECV_ERROR;

	if(recvbuffer[0] != 5)
		return SOCKS_VERSION_ERROR;

	if(recvbuffer[1] != 0)
		return SOCKS_AUTH_REQUIRED;

	addr.sin_port = htons( port );
	addr.sin_addr = *((struct in_addr *)hostx->h_addr);

	memcpy(step_two + 4, &addr.sin_addr.s_addr, 4);
	memcpy(step_two + 8, &addr.sin_port, 2);

	if( send(proxyfd, step_two, 10, 0) != 10 )
		return SOCKS_SEND_ERROR;

	memset(recvbuffer, 0x0, 256);

	if( recv(proxyfd, recvbuffer, 10, 0) < 4 )
		return SOCKS_RECV_ERROR;

	if(recvbuffer[0] != 5)
		return SOCKS_VERSION_ERROR;

	if(recvbuffer[1] != 0)
		return SOCKS_CON_ERROR;

	if(recvbuffer[3] != 1)
		return SOCKS_CON_ERROR;

	return SOCKS_SUCCESS;
}

const char *socks5_str_error(int status){
	static const char *errors[]=
	{
	"error while send data",
	"error whilte receveid data",
	"uncompatible socks version",
	"auth required",
	"connection to target failed",
	"gethostbyname() error"
	};

	if( status < 0 || status > SOCKS_TOTAL)
		return NULL;

	return errors[status-1];
}


void bind_shell(const char *con, int port, const char *proxy, int proxy_port){
	struct pollfd pfds[2];
	int sockfd, i, status;
	char buf[1024], *ip;

	if( proxy != NULL && proxy_port != 0 ){
		printf("[~] Trying connect to proxy server %s:%d\n", proxy, proxy_port);

		if( (sockfd = kadimus_connect(proxy, (unsigned short)proxy_port, &ip)) == -1){
			die("connect() error",1);
		}

		printf("[~] Connected to proxy server !!!\n");
		printf("[~] IP: %s\n", ip);

		printf("[~] Trying connect to target\n");

		if( (status = socks5_connection(sockfd, con, (unsigned short)port)) != SOCKS_SUCCESS ){
			fprintf(stderr, "[-] socks5 connection error: %s\n\n", socks5_str_error(status));
			close(sockfd);
			exit(1);
		}

		printf("[~] Successfully connect to the target\n\n");

	}

	else {

		printf("[~] Trying connect to %s:%d\n", con, port);

		if( (sockfd = kadimus_connect(con, (unsigned short)port, &ip)) == -1){
			die("connect() error", 1);
		}

		printf("[~] Connected !!!\n");
		printf("[~] IP: %s\n\n", ip);

	}

	pfds[1].fd = 0;
	pfds[1].events = POLLIN;
	pfds[0].fd = sockfd;
	pfds[0].events = POLLIN;

	while(1){
		poll(pfds, 2, -1);

		if(pfds[1].revents & POLLIN){
			i = read(0, buf, 1023);

			if(!i)
				break;

			write(sockfd, buf, i);

		}

		if(pfds[0].revents & POLLIN){
			i = read(sockfd, buf, 1023);
			if(!i)
				break;

			write(1, buf, i);
		}

	}

	close(sockfd);
	xfree(ip);

}
