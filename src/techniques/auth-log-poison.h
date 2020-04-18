#ifndef __AUTH_LOG_POISON_H__
#define __AUTH_LOG_POISON_H__

#include "string/url.h"

int auth_log_poison(const char *target, int port);
char *auth_log_rce(const char *target, const char *code);
int check_auth_poison(const char *target);
char *auth_log(url_t *url, const char *auth_file, const char *code, int pos);
void prepare_auth_log_rce(const char *url, const char *ssh_target, int ssh_port);

#endif
