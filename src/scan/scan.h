#ifndef __SCAN_H__
#define __SCAN_H__

#include "string/url.h"

typedef struct {
	char *origurl;
	url_t *url;
	char *origpost;
	char **headers;
	int pos;
	int dynamic;
	int skip_nullbyte;
	int skip_error_check;
	int skip_file_scan;
	int skip_rce_scan;
	int dirback;
} scan_t;

void kadimus_scan(const char *target);

#endif
