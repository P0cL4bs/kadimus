#ifndef __PHP_FILTER_H__
#define __PHP_FILTER_H__

#include "string/url.h"

char *phpfilter(url_t *url, const char *oldurl, const char *filename, int pnumber);

#endif
