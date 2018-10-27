#ifndef KAD_COM
#define KAD_COM

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#define file_print(x...)\
    if(output)\
        fprintf(output, x);

#define print_single(x...)\
    if(!thread_on){\
        fprintf(stdout, x);\
        file_print(x);\
    }

#define print_thread(x...)\
    if(thread_on){\
        fprintf(stdout, x);\
        file_print(x);\
    }

#define print_all(x...)\
    fprintf(stdout, x);\
    file_print(x);


#define color_print_single(color, msg, fmt, args...) do { \
    if(!thread_on) \
        color_print_all(color, msg, fmt, ##args); \
} while(0)

#define color_print_all(color, msg, fmt, args...) do { \
    struct tm *now; \
    time_t t = time(NULL); \
    now = localtime(&t); \
    printf(color "[%02d:%02d:%02d] [" msg "] " fmt "\033[0m", now->tm_hour, now->tm_min, now->tm_sec, ##args); \
    if(output) \
        fprintf(output, "[%02d:%02d:%02d] [" msg "] " fmt ,  \
            now->tm_hour, now->tm_min, now->tm_sec, ##args); \
 } while(0)


#define info_all(fmt, args...) color_print_all("\033[0;32m", "INFO", fmt, ##args)
#define error_all(fmt, args...) color_print_all("\033[0;31m", "ERROR", fmt, ##args)
#define warn_all(fmt, args...) color_print_all("\033[0;33m", "WARNING", fmt, ##args)
#define good_all(fmt, args...) color_print_all("\033[1;32m", "INFO", fmt, ##args)

#define error_single(fmt, args...) color_print_single("\033[0;31m", "ERROR", fmt, ##args)
#define good_single(fmt, args...) color_print_single("\033[1;32m", "INFO", fmt, ##args)
#define info_single(fmt, args...) color_print_single("\033[0;32m", "INFO", fmt, ##args)
#define warn_single(fmt, args...) color_print_single("\033[0;33m", "WARNING", fmt, ##args)

extern FILE *output;
extern bool thread_on;

void die(const char *err, int x);

#endif
