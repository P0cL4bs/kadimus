#ifndef KAD_STR
#define KAD_STR

#include <time.h>
#include <stdint.h>
#include <curl/curl.h>
#include "kadimus_mem.h"
#include "kadimus_common.h"

#define R_SIZE 20
#define M_ALL_SIZE (R_SIZE-1)*2+5
#define VULN_SIZE (R_SIZE-1)*2+11

typedef struct {
	char *key;
	size_t alloc_size_key;
	char *value;
	size_t alloc_size_value;
	bool equal;
} GET_DATA;

typedef enum {
	REPLACE = 1,
	AFTER,
	BEFORE
} M;

GET_DATA *ParserGet(const char *str, size_t *get_data_size);
void free_get_parameters(GET_DATA *GetParameters, size_t elements);
char *gen_random(char *s, const size_t len);
char *make_url(GET_DATA *GetParameters, size_t elements, const char *base_uri, const char *xpl, size_t position, M m);
void extract_url(const char *url, char **base_uri, char **parameters);
char *diff(const char *x, const char *y);
void trim_string(char **diff_str);
bool b64_decode(const char *encode, char **output);
char *b64_encode(const char *x);
void chomp_all(char *str);
char *cookie_append(const char *x, const char *y);
void build_regex(char regex[], char *r_str, char *middle);
char *make_code(const char *mark, const char *code, bool auth);
void print_uri(GET_DATA *GetParameters, const char *base_uri, size_t p_len);
bool get_element_pos(GET_DATA **pp, size_t *pp_len, char **b_uri, const char *uri, const char *p_name, size_t *i_j);
char *urlencode(const char *enc);

#endif

