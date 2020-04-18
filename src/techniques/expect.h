#ifndef __EXPECT_H__
#define __EXPECT_H__

#include "string/url.h"

char *expect_rce(const char *target, const char *parameter, const char *cmd);
char *expect_url(url_t *url, const char *cmd, int pos);

#endif
