#include "base64.h"
#include <string.h>
#include <stdlib.h>

#define b64pos(ch) (strchr(b64, ch)-b64)

static const char b64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

char *b64encode(const char *data, size_t len)
{
	char ch[3], *ret = NULL;
	size_t i, j, pad;

	if (!len)
		goto end;

	ret = malloc(((len + 2) / 3) * 4 + 1);
	if (ret == NULL)
		goto end;

	i = j = 0;

	while (i < len) {
		ch[1] = ch[2] = 0;
		ch[0] = data[i++];

		if (i < len) {
			ch[1] = data[i++];
			if (i < len) {
				ch[2] = data[i++];
			}
		}

		ret[j++] = b64[ch[0] >> 2];
		ret[j++] = b64[(ch[0] & 3) << 4 | ch[1] >> 4];
		ret[j++] = b64[(ch[1] & 0xf) << 2 | ch[2] >> 6];
		ret[j++] = b64[ch[2] & 0x3f];
	}

	pad = len%3;

	if (pad) {
		ret[j - 1] = '=';

		if (pad == 1) {
			ret[j - 2] = '=';
		}
	}

	ret[j] = 0x0;

end:
	return ret;
}

char *b64decode(const char *encoded, size_t *len)
{
	size_t i, pos, strsize;
	char *ret;

	strsize = strlen(encoded);

	if (!isb64valid(encoded, strsize)) {
		return NULL;
	}

	ret = malloc((strsize * 0.75) + 1);

	if (ret == NULL) {
		return NULL;
	}

	i = pos = 0;

	while (i < strsize) {
		ret[pos++] = b64pos(encoded[i]) << 2 | b64pos(encoded[i + 1]) >> 4;

		if (encoded[i + 2] == '=')
			break;

		ret[pos++] = b64pos(encoded[i + 1]) << 4 | b64pos(encoded[i + 2]) >> 2;

		if (encoded[i + 3] == '=')
			break;

		ret[pos++] = b64pos(encoded[i + 2]) << 6 | b64pos(encoded[i + 3]);

		i += 4;
	}

	ret[pos] = 0x0;
	*len = pos;

	return ret;
}

int isb64valid(const char *encoded, size_t length)
{
	size_t i;
	int ret = 0;
	int pos;

	if (!length || length%4)
		goto end;

	for (i=0; i<length; i+=4) {
		if (!(strchr(b64, encoded[i])) || !(strchr(b64, encoded[i + 1]))) {
			goto end;
		}

		if (length != i + 4) {
			if (!(strchr(b64, encoded[i + 2])) || !(strchr(b64, encoded[i + 3]))) {
				goto end;
			}
		}
	}

	if (encoded[i - 2] == '=') {
		if (encoded[i - 1] != '=') {
			goto end;
		}

		/* check if the first 4 bits are set */
		pos = strchr(b64, encoded[i - 3]) - b64;

		if (pos & 0xf)
			goto end;

	} else if (encoded[i - 1] == '=') {
		pos = strchr(b64, encoded[i - 2]) - b64;
		if (pos & 3)
			goto end;
	}


	ret = 1;

end:
	return ret;
}
