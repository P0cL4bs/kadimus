#ifndef __DATAWRAP_H__
#define __DATAWRAP_H__

#include "string/url.h"

char *datawrap_rce(url_t *url, const char *code, int pos);
char *data_wrap_rce(const char *target, const char *parameter, const char *code);

#endif
