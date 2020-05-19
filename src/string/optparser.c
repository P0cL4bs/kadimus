#include "optparser.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void optparser(int argc, char **argv, optparser_t *opts, int len)
{
	struct option *options;
	char *shortopts;
	int opt_index = 0;

	// alloc memory using just one malloc call
	// (len * 2 + 1) -> len is the max number of short opts possible
	// multiplied by two for include ':', and +1 for null byte
	// (len + 1) because getopt_long need an empty struct
	shortopts = malloc((len * 2 + 1) + sizeof(struct option) * (len + 1));
	options = (struct option *)(shortopts + len * 2 + 1);

	char ***remain = NULL;

	char *shortaux = shortopts;
	struct option *optaux = options;

	for (int i = 0; i < len ; i++) {
		if (opts[i].name && !strcmp("*", opts[i].name)) {
			remain = opts[i].var;
			continue;
		}

		if (!opts[i].name)
			goto setshortopt;

		optaux->name = opts[i].name;
		optaux->has_arg = (opts[i].argtype != optnoarg && opts[i].argtype != optbool);

		if (opts[i].argtype == optnoarg)
			optaux->flag = opts[i].var;
		else
			optaux->flag = NULL;

		optaux->val = opts[i].shortopt;
		optaux++;

setshortopt:
		if (isalpha(opts[i].shortopt) || isdigit(opts[i].shortopt)) {
			*shortaux++ = opts[i].shortopt;

			if (opts[i].argtype != optnoarg && opts[i].argtype != optbool)
				*shortaux++ = ':';
		}
	}

	memset(optaux, 0x0, sizeof(struct option));
	*shortaux = 0x0;

	int opt;

	while ((opt = getopt_long(argc, argv, shortopts, options, &opt_index)) != -1) {
		optparser_t *current_opt = NULL;

		for (int i = 0; i < len; i++) {
			if (!opt) {
				if (!strcmp(opts[i].name, options[opt_index].name)) {
					current_opt = opts + i;
					break;
				}
			} else if (opt == opts[i].shortopt) {
				current_opt = opts + i;
				break;
			}
		}

		if (!current_opt)
			exit(EXIT_FAILURE);

		if (current_opt->var && (optarg || current_opt->argtype == optbool)) {
			switch (current_opt->argtype) {
				case optstring:
					*(char **) current_opt->var = optarg;
					break;
				case optint:
					*(int *) current_opt->var = atoi(optarg);
					break;
				case optlong:
					*(long *) current_opt->var = strtol(optarg, NULL, 10);
					break;
				case optbool:
					*(int *) current_opt->var = 1;
			}
		}

		if (current_opt->optcb)
			current_opt->optcb(current_opt->var, optarg);
	}

	if (remain)
		*remain = argv + optind;

	free(shortopts);
}
