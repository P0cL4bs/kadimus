#include "kadimus_socket.h"

void pollfd_proxy(struct pollfd *pfds);
int socks5_connection(int proxyfd, const char *host, unsigned short port);
const char *socks5_str_error(int status);

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
    struct addrinfo hints, *servinfo, *addr;
    int status, sockfd, ret = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    if((status = getaddrinfo(hostname, NULL, &hints, &servinfo))){
        fprintf(stderr, "[-] getaddrinfo: %s\n", gai_strerror(status));
        exit(1);
    }

    for(addr=servinfo; addr; addr=addr->ai_next){
        if((sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol)) == -1)
            continue;

        void *ai_addr = addr->ai_addr;
        if(addr->ai_family == AF_INET){
            ((struct sockaddr_in *)ai_addr)->sin_port = htons(port);
        } else {
            ((struct sockaddr_in6 *)ai_addr)->sin6_port = htons(port);
        }

        if(connect(sockfd, addr->ai_addr, addr->ai_addrlen) == -1){
            close(sockfd);
            continue;
        }

        break;
    }

    if(!addr)
        goto end;

    if(ip){
        if(addr->ai_family == AF_INET){
            xmalloc(*ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &((struct sockaddr_in *)(addr->ai_addr))->sin_addr, *ip, INET_ADDRSTRLEN);
        }

        else if(addr->ai_family == AF_INET6){
            xmalloc(*ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)(addr->ai_addr))->sin6_addr, *ip, INET6_ADDRSTRLEN);
        }
    }

    ret = sockfd;
    end:
    freeaddrinfo(servinfo);
    return ret;
}

void start_listen(int *sock_fd, int port){
    struct sockaddr_in server_addr;
    int optval = 1;

    if( (*sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        xdie("socket() failed\n");

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    bzero(&(server_addr.sin_zero), 8);

    if(setsockopt(*sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval) == -1)
        xdie("setsockopt() failed\n");

    if(bind(*sock_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
        xdie("bind() failed\n");

    if(listen(*sock_fd,1) == -1)
        xdie("listen() failed\n");

}

void start_bind_shell(int port){
    char ip_connection[INET6_ADDRSTRLEN];
    struct sockaddr cli_addr;
    int sock, ret, sockfd;
    struct pollfd pfds[2];
    pid_t pid;

    socklen_t sockaddr_len = sizeof(struct sockaddr_in);
    start_listen(&sock, port);

    pfds[0].fd = sock;
    pfds[0].events = POLLIN;

    pid = getpid();
    info("[pid: %d] listen on port: %d\n", pid, port);
    info("[pid: %d] waiting connection ...\n", pid);

    ret = poll(pfds, 1, LISTEN_TIMEOUT*1000);

    if(ret == -1)
        xdie("poll() failed\n");
    else if(!ret){
        error("[pid: %d] connection timeout %d !!!\n", pid, LISTEN_TIMEOUT);
        exit(0);
    }

    if((sockfd = accept(sock, (struct sockaddr *) &cli_addr, &sockaddr_len)) == -1 )
        xdie("accept() failed\n");

    if(cli_addr.sa_family == AF_INET){
        inet_ntop(AF_INET, &((struct sockaddr_in *)&cli_addr)->sin_addr, ip_connection, INET_ADDRSTRLEN);
    } else if(cli_addr.sa_family == AF_INET6){
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&cli_addr)->sin6_addr), ip_connection, INET6_ADDRSTRLEN);
    } else {
        strcpy(ip_connection, "unknow");
    }

    good("[pid: %d] new connection from: %s\n", pid, ip_connection);

    pfds[0].fd = sockfd;
    pfds[0].events = POLLIN;
    pfds[1].fd = 0;
    pfds[1].events = POLLIN;

    pollfd_proxy(pfds);

    exit(0);
}


void remote_connect(const char *con, int port, const char *proxy){
    struct pollfd pfds[2];
    int sockfd, status, pport;
    char *ip, *aux, *host, *ptr;

    if(proxy){
        printf("[~] Trying connect to proxy server: %s\n", proxy);

        ptr = strdup(proxy);
        host = strstr(ptr, "://")+3;
        aux = strchr(host, ':');
        *aux = 0x0;
        pport = atoi(aux+1);

        if( (sockfd = kadimus_connect(host, (unsigned short)pport, &ip)) == -1){
            xdie("connect() failed\n");
        }

        free(ptr);

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

        info("trying connect to %s:%d\n", con, port);

        if((sockfd = kadimus_connect(con, (unsigned short)port, &ip)) == -1){
            xdie("connect() failed\n");
        }

        good("connected, ip: %s!!!\n", ip);
    }

    pfds[1].fd = 0;
    pfds[1].events = POLLIN;
    pfds[0].fd = sockfd;
    pfds[0].events = POLLIN;

    pollfd_proxy(pfds);

    close(sockfd);
    free(ip);
}

void pollfd_proxy(struct pollfd *pfds){
    char buf[1024];
    ssize_t nbytes;
    int i, ok = 1;

    while(ok){
        if(poll(pfds, 2, -1) == -1)
            break;

        for(i=0; i<2; i++){
            if(pfds[i].revents & POLLIN){
                if((nbytes = read(pfds[i].fd, buf, sizeof(buf))) <= 0){
                    ok = 0;
                    break;
                }

                write(pfds[(i+1)%2].fd, buf, nbytes);
            }
        }
    }
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
