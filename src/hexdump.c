#include "hexdump.h"

#include <string.h>
#include <stdio.h>

static const char hextable[]="0123456789abcdef";

void hexdump(const char *ptr, size_t len){
    char hex[80], *aux, ch;

    size_t i = 0, total;
    int offset, ch_offset;
    unsigned int count = 0;

    while(i<len){
        offset = sprintf(hex, "0x%08x:  ", count);
        aux = hex+offset;
        ch_offset = 41;
        offset = 0;

        total = i+16;
        if(total > len)
            total = len;

        for(; i<total; i++){
            ch = ptr[i];
            aux[offset++] = hextable[ch/16];
            aux[offset++] = hextable[ch%16];
            aux[ch_offset++] = (ch > ' ' && ch <= '~') ? ch : '.';

            if(i%2)
                aux[offset++] = ' ';
        }

        aux[ch_offset] = 0x0;
        memset(aux+offset, ' ', 41-offset);

        puts(hex);
        count += 16;


        i = total;
    }
}
