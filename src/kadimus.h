#ifndef KADIMUS_H
#define KADIMUS_H

#define VERSION "1.1"
#define IN_RANGE(a,b,c) ((a >= b && a <= c) ? 1 : 0)
#define OPTS "hB:A:u:U:t:X:C:F:c:srbi:p:Gf:o:nl:O:"

struct all_opts {
	char *url;
	char *ip_addr;
	char *filename;
	char *b_proxy;
	FILE *url_list;
	FILE *source_output;
	size_t port;
	size_t listen;
	size_t threads;
	int b_port;
	bool bind_shell;
	bool reverse_shell;
	bool shell;
	bool get_source;
};

void parser_opts(int argc, char **argv);
void banner(void);
void help(void);
int main(int argc, char **argv);

#endif
