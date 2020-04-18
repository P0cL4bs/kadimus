#ifndef __PHP_FILTER_H__
#define __PHP_FILTER_H__

#include "string/url.h"
#include <stdio.h>

char *phpfilter(url_t *url, const char *oldurl, const char *filename, int pnumber);
void phpfilter_dumpfile(FILE *, const char *, const char *, const char *);

#endif
