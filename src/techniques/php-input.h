#ifndef __PHP_INPUT_H__
#define __PHP_INPUT_H__

#include "string/url.h"

char *php_input(url_t *url, const char *input, const char *code, int pos);
char *php_input_rce(const char *target, const char *code);

#endif
