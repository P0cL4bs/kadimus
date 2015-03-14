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
	int sock, i;
	struct sockaddr cli_addr;
	struct pollfd pfds[2];
	char ip_connection[INET6_ADDRSTRLEN] = {0};
	char buf[1024];


	socklen_t sockaddr_len = sizeof(struct sockaddr_in);
	start_listen(&sock, port);


	int sock_con = 0;

	printf("Listen in background, port: %d, pid: %lld\nWaiting connection ...\n", port, (long long int) getpid());

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

void bind_shell(const char *con, int port){
	struct addrinfo hints, *servinfo, *p;
	struct pollfd pfds[2];
	int rv, sockfd, i;
	char ipv6[INET6_ADDRSTRLEN], ipv4[INET_ADDRSTRLEN], buf[1024];

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	printf("[~] Trying connect to %s:%d\n", con, port);

	if ((rv = getaddrinfo(con, NULL, &hints, &servinfo)) != 0) {
		fprintf(stderr, "[-] getaddrinfo: %s\n", gai_strerror(rv));
		exit(1);
	}


	for(p = servinfo; p != NULL; p = p->ai_next) {
		if(AF_INET6 == p->ai_family){
			inet_ntop(AF_INET6, &((struct sockaddr_in6 *)(p->ai_addr))->sin6_addr, ipv6, INET6_ADDRSTRLEN);
			printf("[+] Ipv6: %s\n", ipv6);
		}

		else if(AF_INET == p->ai_family) {
			inet_ntop(AF_INET, &((struct sockaddr_in *)(p->ai_addr))->sin_addr, ipv4, INET_ADDRSTRLEN);
			printf("[+] Ipv4: %s\n", ipv4);
		}

		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("[-] socket error");
			continue;
		}

		((struct sockaddr_in *)p->ai_addr)->sin_port = htons(port);

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("[-] connect error");
			continue;
		}

		break;
	}

	if(!p){
		printf("[-] Can't connect to %s:%d\n\n",con, port);
		freeaddrinfo(servinfo);
		return;
	}

	freeaddrinfo(servinfo);

	printf("[~] Connected !!!\n\n");


	pfds[1].fd = 0;
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



}
