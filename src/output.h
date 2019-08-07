#ifndef __OUTPUT_H__
#define __OUTPUT_H__

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

#define eprint(x...) fprintf(stderr, x);

#define print_all(x...) do { \
    fprintf(stdout, x); \
    if(output) \
        fprintf(output, x); \
} while(0);

#define print_thread(x...) do { \
    if(thread_enable) \
        print_all(x) \
} while(0)

#define xdie(fmt, args...) do { \
    eprint("[%s:%s:%d] " fmt, __FILE__, __FUNCTION__, __LINE__, ##args); \
    exit(1); \
} while(0)

#define die(args...) do { \
    eprint(args); \
    exit(1); \
} while(0)

#define msg(color, type, fmt, args...) do { \
    struct tm *now; \
    time_t t = time(NULL); \
    now = localtime(&t); \
    printf(color "[%02d:%02d:%02d] [" type "] " fmt "\033[0m", \
        now->tm_hour, now->tm_min, now->tm_sec, ##args); \
    if(output){ \
        fprintf(output, "[%02d:%02d:%02d] [" type "] " fmt, \
            now->tm_hour, now->tm_min, now->tm_sec, ##args); \
    } \
} while(0)

#define xmsg(color, type, fmt, args...) do { \
    if(!thread_enable) \
        msg(color, type, fmt, ##args); \
} while(0)

#define error(fmt, args...)  msg("\033[0;31m", "ERROR",   fmt, ##args)
#define info(fmt, args...)   msg("\033[0;32m", "INFO",    fmt, ##args)
#define warn(fmt, args...)   msg("\033[0;33m", "WARNING", fmt, ##args)
#define good(fmt, args...)   msg("\033[1;32m", "INFO",    fmt, ##args)

#define xerror(fmt, args...) xmsg("\033[0;31m", "ERROR",   fmt, ##args)
#define xinfo(fmt, args...)  xmsg("\033[0;32m", "INFO",    fmt, ##args)
#define xwarn(fmt, args...)  xmsg("\033[0;33m", "WARNING", fmt, ##args)
#define xgood(fmt, args...)  xmsg("\033[1;32m", "INFO",    fmt, ##args)


// globals
extern FILE *output;
extern int thread_enable;

#endif
