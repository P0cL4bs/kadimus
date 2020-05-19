#ifndef __OPTPARSER_H__
#define __OPTPARSER_H__

typedef struct {
	char *name;
	void *var;
	void (*optcb)(void *, const char *);
	int argtype;
	int shortopt;
} optparser_t;

enum {
	optnoarg,
	optint,
	optstring,
	optlong,
	optbool,
	optcustom
};

/*
#define optparser(argc, argv, ...) {\
	optparser_t mopts[] = { \
		__VA_ARGS__ \
	}; \
	_optparser(argc, argv, mopts, sizeof(mopts) / sizeof(optparser_t)); \
} while (0)
*/

void optparser(int argc, char **argv, optparser_t *opts, int len);


#endif
