#include "kadimus_str.h"

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const int nbytes[] = { 3, 1, 1, 2 };

static void xlate(unsigned char *in, unsigned char *out){
	out[0] = in[0] << 2 | in[1] >> 4;
	out[1] = in[1] << 4 | in[2] >> 2;
	out[2] = in[2] << 6 | in[3] >> 0;
}

char *b64_encode(const char *x){
	char *encoded_str = NULL, *ret = NULL;
	size_t size_str = 0, n = 0, pos = 0, i = 0;
	uint8_t b[3], c[4];

	size_str = strlen(x);

	encoded_str = xmalloc( ((size_str * 4)/3) + (size_str/96) + 10 );

	b[0]=0; b[1]=0; b[2]=0;

	while(x[i]){
		n = 0;
		b[0]=x[i];
		i++;
		n++;

		if(x[i]){
			b[1]=x[i];
			i++;
			n++;
		}

		if(x[i]){
			b[2]=x[i];
			x++;
			n++;
		}

		c[0] = b64[((b[0] & 0xFC) >> 2)];
		c[1] = b64[(b[0] & 0x03) << 4 | (b[1] & 0xF0) >> 4];
		c[2] = b64[(b[1] & 0x0F) << 2 | (b[2] & 0xC0) >> 6];
		c[3] = b64[b[2] & 0x3F];

		encoded_str[pos] = c[0];
		pos++;

		encoded_str[pos] = c[1];
		pos++;

		if( n == 1 ){
			encoded_str[pos] = '=';
			pos++;
			encoded_str[pos] = '=';
			pos++;
		}

		else if( n == 2 ){
			encoded_str[pos] = c[2];
			pos++;
			encoded_str[pos] = '=';
			pos++;
		}

		else {
			encoded_str[pos] = c[2];
			pos++;
			encoded_str[pos] = c[3];
			pos++;
		}

		b[0]=0;b[1]=0;b[2]=0;
	}

	encoded_str[pos] = 0x0;
	ret = urlencode(encoded_str);
	xfree(encoded_str);

	return ret;

}

bool b64_decode(const char *encode, char **output){
	int phase = 0, i;
	unsigned char in[4], out[3];
	size_t len_str = 0, alloc_size = 0 , j = 0;
	char *p;

	*out = (unsigned char) 0;
	*in = (unsigned char) 0;

	len_str = strlen(encode);

	if(len_str % 4 != 0 || len_str == 0)
		return false;

	if(encode[len_str-1] == '=' && encode[len_str-2] == '=')
		len_str -= 2;
	else if(encode[len_str-1] == '=')
		len_str--;

	alloc_size = (size_t)len_str*0.75;
	(*output) = xmalloc( alloc_size+1 );

	while(*encode){
		if(*encode == '='){
			xlate(in, out);
			for(i=0; i <nbytes[phase]; i++,j++)
				(*output)[j] = (char) out[i];
			break;
		}

		p = strchr(b64, *encode);

		if(p){

			in[phase] = p-b64;
			phase = (phase+1)%4;

			if(phase == 0){
				xlate(in, out);
				in[0]=in[1]=in[2]=in[3]=0;

				for(i=0; i < nbytes[phase]; i++, j++)
					(*output)[j] = (char) out[i];
			}

		} else {
			break;
		}

		encode++;
	}

	if(j != alloc_size){
		xfree(*output);
		return false;
	}

	(*output)[j] = 0x0;
	return true;
}

char *urlencode(const char *enc){
	int i, j, len;
	char *ret, x;

	static const char hextable[]="0123456789abcdef";

	ret=xmalloc(1);
	len=1;

	for(i=0, j=0; enc[i]; i++, j++){
		x = enc[i];
		len++;
		ret = xrealloc(ret, len);

		if( (x >= 'a' && x <= 'z') ||
		    (x >= 'A' && x <= 'Z') ||
		    (x >= '0' && x <= '9')
		){
			ret[j] = x;
		}

		else {
			len += 2;
			ret = xrealloc(ret, len);
			ret[j] = '%';

			ret[j+1] = hextable[((x/16)%16)];
			ret[j+2] = hextable[x%16];

			j+=2;
		}
	}

	ret[j] = 0x0;

	return ret;

}

static size_t GetElements(const char *str){
	size_t elements = 1, i = 0;

	for(i=0;str[i];i++)
		if(str[i] == '&')
			elements++;

	return elements;
}

static void init_elements(GET_DATA *GetParameters, size_t elements){
	size_t i;

	for(i=0; i < elements; i++){
		GetParameters[i].key = NULL;
		GetParameters[i].alloc_size_key = 1;
		GetParameters[i].value = NULL;
		GetParameters[i].alloc_size_value = 1;
		GetParameters[i].equal = false;
	}

}

static void alloc_elements(GET_DATA * GetParameters, const char *str){
	size_t i = 0, p = 0;

	for(i=0; str[i]; i++){
		if(str[i] == '&'){
			GetParameters[p].key = xmalloc( GetParameters[p].alloc_size_key );
			GetParameters[p].value = xmalloc( GetParameters[p].alloc_size_value );
			GetParameters[p].equal = false;
			p++;
		}

		else if(str[i] == '=') {
			if(GetParameters[p].equal)
				GetParameters[p].alloc_size_value++;
			else
				GetParameters[p].equal = true;

		}

		else {
			if(GetParameters[p].equal)
				GetParameters[p].alloc_size_value++;
			else
				GetParameters[p].alloc_size_key++;
		}

	}

	GetParameters[p].key = xmalloc( GetParameters[p].alloc_size_key );
	GetParameters[p].value = xmalloc( GetParameters[p].alloc_size_value );
	GetParameters[p].equal = false;

}

static void write_struct(GET_DATA *GetParameters, const char *str){
	size_t i = 0, p = 0, j = 0;

	for(i=0; str[i]; i++){
		if(str[i] == '&'){

			GetParameters[p].key[ GetParameters[p].alloc_size_key-1 ] = 0x0;
			GetParameters[p].value[ GetParameters[p].alloc_size_value-1 ] = 0x0;
			j = 0;
			p++;

		} else if(str[i] == '='){

			if(GetParameters[p].equal){
				GetParameters[p].value[j] = str[i];
				j++;
			} else {
				j = 0;
				GetParameters[p].equal = true;
			}

		} else {

			if(GetParameters[p].equal)
				GetParameters[p].value[j] = str[i];
			else
				GetParameters[p].key[j] = str[i];
			j++;
		}
	}

	GetParameters[p].key[ GetParameters[p].alloc_size_key-1 ] = 0x0;
	GetParameters[p].value[ GetParameters[p].alloc_size_value-1 ] = 0x0;

}

GET_DATA *ParserGet(const char *str, size_t *get_data_size){
	size_t elements = 0;
	GET_DATA *GetParameters = NULL;

	elements = GetElements(str);
	GetParameters = xmalloc( elements * sizeof(GET_DATA));

	init_elements(GetParameters, elements);
	alloc_elements(GetParameters, str);
	write_struct(GetParameters, str);

	*get_data_size = elements;
	return GetParameters;

}

void free_get_parameters(GET_DATA *GetParameters, size_t elements){
	size_t i = 0;

	for(i=0; i < elements; i++){
		xfree(GetParameters[i].key);
		xfree(GetParameters[i].value);
	}

	xfree(GetParameters);
}

char *gen_random(char *s, const size_t len){
	//(void)rand();
	static const char alphanum[] =
	"0123456789"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz";

	size_t i;

	for(i=0; i<len; i++){
		//srand(time(NULL));
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[i] = 0x0;

	return s;
}

char *make_url(
	GET_DATA *GetParameters,
	size_t elements,
	const char *base_uri,
	const char *xpl,
	size_t position,
	M m){

	char *new_url = NULL;
	size_t alloc_size = 2 , i = 0, len = 0, xpl_len = 0;

	len = strlen(base_uri);
	xpl_len = strlen(xpl);

	alloc_size += len+xpl_len;

	for(i=0; i < elements; i++){
		alloc_size += GetParameters[i].alloc_size_key-1;

		if(i != elements-1)
			alloc_size++;

		if(GetParameters[i].equal)
			alloc_size++;

		if(i == position && m == REPLACE){
				continue;
		}

		alloc_size += GetParameters[i].alloc_size_value-1;
	}

	new_url = xmalloc( alloc_size );
	strncpy(new_url, base_uri , len);

	new_url[len] = '?';
	new_url[len+1] = 0x0;

	for(i=0; i < elements ; i++){
		if(GetParameters[i].alloc_size_key-1 != 0)
			strncat(new_url, GetParameters[i].key, GetParameters[i].alloc_size_key-1);

		if(GetParameters[i].equal)
			strncat(new_url, "=", 1);

		if(i == position) {
			if(m == REPLACE){
				strncat(new_url, xpl, xpl_len);
			} else if(m == AFTER){
				strncat(new_url, GetParameters[i].value, GetParameters[i].alloc_size_value-1);
				strncat(new_url, xpl, xpl_len);
			} else if(m == BEFORE){
				strncat(new_url, xpl, xpl_len);
				strncat(new_url, GetParameters[i].value, GetParameters[i].alloc_size_value-1);
			}
		} else {
			if(GetParameters[i].alloc_size_value-1 != 0)
				strncat(new_url, GetParameters[i].value, GetParameters[i].alloc_size_value-1);
		}

		if( i != elements-1 )
			strncat(new_url, "&", 1);

	}

	return new_url;

}

void extract_url(const char *url, char **base_uri, char **parameters){
	size_t i = 0, end = 0, j = 0,
	len = strlen(url);

	for(i=0; i<len; i++){
		if(url[i] == '?'){
			end = i;
			break;
		}
	}

	if(end == 0 || end == len-1)
		return;

	*base_uri = strncpy( xmalloc( end+1 ) , url, end );
	(*base_uri)[end] = 0x0;

	*parameters = xmalloc( len-end );

	end++;

	for(i=end, j = 0; i<len; i++, j++)
		(*parameters)[j] = url[i];

	(*parameters)[j] = 0x0;

}

char *diff(const char *x, const char *y){
	char *ret = NULL;
	int j = 0, i = 0, len_x = strlen(x), len_y = strlen(y),
	tmp = 0, tmp2 = 0, alloc_size = 0;


	if(len_x == 0 || len_y == 0)
		return NULL;
	//printf("len_x %d , len_y %d\n",len_x, len_y);

	for(i=0; x[i] && y[i] && x[i] == y[i]; i++);
	tmp = i;

	for(i=len_x-1 , j=len_y-1; j >= 0 && x[i] == y[j]; i--, j--);
	j++;
	tmp2 = j;

	if(tmp2 <= tmp)
		return NULL;

	alloc_size = 1+tmp2-tmp;

	ret = xmalloc( alloc_size );

	for( i=tmp, j=0; i < tmp2 ; i++, j++)
		ret[j] = y[i];
	ret[j] = 0x0;

	return ret;
}

void trim_string(char **diff_str){
	size_t i = 0, j = 0, start = 0, end = 0;
	char *aux = NULL;

	for(i=0; (*diff_str)[i]; i++)
		if((*diff_str)[i] != '\n' && (*diff_str)[i] != ' ' && (*diff_str)[i] != '\t')
			break;

	//if(! (*diff_str)[i] )
	//	return;

	start = i;

	for(i=start; (*diff_str)[i]; i++)
		if((*diff_str)[i] != '\n' && (*diff_str)[i] != ' ' && (*diff_str)[i] != '\t')
			break;

	end = i;

	if(end-start == 0)
		return;

	aux = xmalloc( 1+end-start );

	for(i=start, j=0; i < end; i++, j++)
		aux[j] = (*diff_str)[i];

	aux[j] = 0x0;
	xfree(diff_str);

	*diff_str = xstrdup(aux);

	xfree(aux);

	return;
}


void chomp_all(char *str){
	while(*str){
		if(*str == '\n')
			*str = ' ';
		str++;
	}
}

char *cookie_append(const char *x, const char *y){
	char *ret = NULL;
	size_t i,j;
	ret = xmalloc( strlen(x)+strlen(y)+2 );

	for(i=0, j=0; x[i]; i++, j++)
		ret[j] = x[i];

	ret[j] = '&';
	j++;

	for(i=0; y[i]; i++, j++)
		ret[j] = y[i];

	ret[j] = 0x0;

	return ret;
}

void build_regex(char regex[], char *r_str, char *middle){
	size_t i , j;

	for(i=0,j=0; r_str[i]; i++, j++)
		regex[j] = r_str[i];

	for(i=0; middle[i]; i++, j++)
		regex[j] = middle[i];

	for(i=0; r_str[i]; i++, j++)
		regex[j] = r_str[i];

	regex[j] = 0x0;


}

char *make_code(const char *mark, const char *code, bool auth){
	char *ret = NULL, *b64x=NULL, *xpl_auth;
	size_t len = 0, encode_auth_len;

	if(!auth){
		len = strlen(mark)*2+strlen(code)+2;
		ret = xmalloc( len );
		snprintf(ret, len, "%s%s%s",mark,code,mark);
	} else {
		ret = xmalloc( strlen(mark)*2+17*2+strlen(code)+2 );
		sprintf(ret, "<?php echo \"%s\"; ?>%s<?php echo \"%s\"; ?>", mark, code, mark);
		b64x = b64_encode(ret);

		//encode_auth_len  = strlen(lol);
		//encode_auth = urlencode(lol);

		encode_auth_len = strlen(b64x)+18+1;

		xpl_auth = strcpy( xmalloc( (encode_auth_len+1) ), "stairway_to_heaven=");
		strcat(xpl_auth, b64x);

		//xfree(encode_auth);
		xfree(ret);
		xfree(b64x);
		return xpl_auth;
	}

	return ret;
}

void print_uri(GET_DATA *GetParameters, const char *base_uri, size_t p_len){
	size_t i;

	print_all("%s?",base_uri);

	for(i=0; i < p_len; i++){
		print_all("%s", GetParameters[i].key);

		if(GetParameters[i].equal) {
			print_all("=");
		}

		else {
			continue;
		}

		print_all("%s", GetParameters[i].value);
	}

}

bool get_element_pos(GET_DATA **pp, size_t *pp_len, char **b_uri, const char *uri, const char *p_name, size_t *i_j){
	char *parameters=NULL;
	size_t i;

	extract_url(uri, &(*b_uri), &parameters);

	if(!*b_uri || !parameters){
		xfree(*b_uri);
		xfree(parameters);
		return false;
	}

	*pp = ParserGet(parameters, pp_len);
	xfree(parameters);

	for(i=0; i < (*pp_len); i++){
		if(!strcmp(p_name, pp[i]->key) && pp[i]->equal){
			*i_j = i;
			return true;
		}
	}

	xfree(*b_uri);
	free_get_parameters(*pp, *pp_len);

	return false;

}
