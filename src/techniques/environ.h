#ifndef __ENVIRON_H__
#define __ENVIRON_H__

#include "string/url.h"

char *proc_env_url(url_t *url, const char *envfile, const char *code, int pos);
char *proc_env_rce(const char *target, const char *code);

#endif
