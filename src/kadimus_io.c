#include "kadimus_io.h"

FILE *xfopen(const char *file, const char *mode){
	FILE *x = NULL;
	if( (x = fopen(file,mode)) == NULL) {
		fprintf(stderr, "(%s)",file);
		die(" fopen() error ",1);
	}

	return x;
}


size_t get_max_len(FILE *fh){
	char c;
	size_t count = 0, max = 0;

	while( (c = fgetc(fh)) != EOF){
		if(c == '\n'){
			if(max < count)
				max = count;
			count = 0;

		}
		else
			count++;
	}

	fseek(fh,0,SEEK_SET);

	return max;

}

int readline(FILE *fh, char *line, size_t len){
	size_t p = 0;
	char c;

	while( (c = fgetc(fh)) != EOF ){
		if(c == '\n' || p == len)
			break;
		line[p] = c;
		p++;
	}

	line[p] = 0x0;

	return (c == EOF) ? 0 : 1;
}

FILE *get_random_file(size_t retry, char tmp_name[]){
	FILE *x=NULL;
	size_t i=0;
	int check;
	strcpy(tmp_name, "/tmp/kadimus-XXXXXX");
	
	for(i=0;i<=retry;i++){
		check = mkstemp(tmp_name);
		if(check){
			close(check);
			unlink(tmp_name);
		}
		
		if( (x = fopen(tmp_name,"w+")) )
			return x;
	}

	return NULL;
	
}

int get_file_size(int fd){
	struct stat s;
	
	if(fstat(fd, &s) == -1){
		die("fstat() error",1);
	}

	return s.st_size;

}

int readonly(const char *name){
	int ret = open(name, O_RDONLY);

	if(ret == -1)
		die("open() error",1);

	return ret;
}
