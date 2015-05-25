#include "kadimus_common.h"

FILE *output;
bool thread_on;

void die(const char *err, int x){
	(x) ? perror(err) : fprintf(stderr, "%s\n", err);
	exit(1);
}


void hex_print(const char *x){
	size_t i = 0, size = strlen(x), pf = 0,
	aux = 0, count = 0, tot = 0;

	while(1){
		print_all("\t0x%03d0: ",(int)count);

		(tot+16 > size) ? (tot = size) : (tot += 16);

		for(i=aux;i<tot;i+=2){
			pf += print_all(" %02x",(unsigned int)(*(unsigned char*)(&x[i])));

			if(i+1 != tot){
				pf += print_all("%02x",(unsigned int)(*(unsigned char*)(&x[i+1])));
			}
		}

		print_all("%-*s",42-(int)pf,"");

		for(i=aux;i<tot;i++){
			print_all("%c",(x[i] > 32 && x[i] < 127) ? x[i] : '.');
		}

		count++;

		print_all("\n");
		pf = 0;

		if(i >= size)
			break;

		aux += 16;
	}
}
