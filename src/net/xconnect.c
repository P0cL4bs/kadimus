#include "net/xconnect.h"
#include "memory/alloc.h"
#include "output.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

int xconnect(char **ip, const char *target, uint16_t port){
    struct addrinfo hints, *res;
    int errcode, fd;
    void *aux;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    if((errcode = getaddrinfo(target, NULL, &hints, &res))){
        die("getaddrinfo failed: %s\n", gai_strerror(errcode));
    }

    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(fd == -1){
        goto end;
    }

    if(res->ai_family == AF_INET){
        ((struct sockaddr_in *) res->ai_addr)->sin_port = htons(port);
    } else {
        ((struct sockaddr_in6 *) res->ai_addr)->sin6_port = htons(port);
    }

    if(connect(fd, res->ai_addr, res->ai_addrlen) == -1){
        close(fd);
        fd = -1;
        goto end;
    }

    if(ip){
        xmalloc(*ip, INET6_ADDRSTRLEN);
        if(res->ai_family == AF_INET){
            aux = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
        } else {
            aux = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
        }

        inet_ntop(res->ai_family, aux, *ip, INET6_ADDRSTRLEN);
    }


    end:
    freeaddrinfo(res);
    return fd;
}
