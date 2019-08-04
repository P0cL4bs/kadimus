#include "hexdump.h"

#include <string.h>
#include <stdio.h>

static const unsigned char hextable[]="0123456789abcdef";

void hexdump(void *data, size_t len, int squeez){
    char hex[69], *prev = NULL;
    unsigned ch;

    size_t i = 0, total, hexoffset, choffset;
    int asterisk = 0;

    while(i < len){
        hexoffset = 11;
        choffset = 52;

        sprintf(hex, "%08x:", (unsigned int)i);
        memset(hex+9, ' ', 43);

        total = i + 16;
        if(total > len){
            total = len;
        } else if(squeez && prev){
            if(memcmp(prev, (char *)data + i, 16) == 0x0){
                prev = (char *)data + i;
                i += 16;

                if(!asterisk){
                    puts("*");
                    asterisk = 1;
                }

                continue;
            } else {
                asterisk = 0;
            }
        }

        prev = (char *)data + i;

        while(i < total){
            ch = ((unsigned char *)data)[i];
            hex[choffset++] = (ch > ' ' && ch <= '~') ? ch : '.';

            hex[hexoffset++] = hextable[ch / 16];
            hex[hexoffset++] = hextable[ch % 16];

            if(i % 2) hexoffset++;

            i++;
        }

        hex[choffset] = 0x0;

        puts(hex);
    }

    printf("%08x\n", (unsigned int)i);
}
