#include "kadimus_common.h"

FILE *output;
bool thread_on;

void die(const char *err, int x){
    (x) ? perror(err) : fprintf(stderr, "%s\n", err);
    exit(1);
}
