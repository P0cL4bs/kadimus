#ifndef __NET_UTILS_H__
#define __NET_UTILS_H__

#include <stdint.h>

int checkhostname(const char *hostname);
void bindshell(uint16_t port);
void remote_connect(const char *proxy, const char *target, uint16_t port);

#endif
