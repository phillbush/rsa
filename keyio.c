#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "bignum.h"
#include "keyio.h"

#define BASE64_ALPHASIZE        64
#define BASE64_SHIFT            3

enum {
	SEQUENCE = 0x30,
	INTEGER  = 0x02,
};

static char base64alpha[BASE64_ALPHASIZE] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
};

static size_t
nbytes(size_t m)
{
	size_t size;
	unsigned int n;

	size = 0;
	for (n = *((unsigned int *)(&m)); n > 0; n >>= CHAR_BIT)
		size++;
	return size;
}

int
keywrite(FILE *fp, Bignum *nums[], size_t nnums)
{
	size_t bufsize, size, plsize, i;
	uint32_t u;
	int ret = 0;
	int n;
	uint8_t *buf = NULL;
	uint8_t *p;

	/* compute buffer size; and allocate buffer */
	bufsize = 0;
	for (i = 0; i < nnums; i++) {
		size = bignum_siz(nums[i]);
		bufsize++;                      /* for the integer header */
		bufsize += nbytes(nbytes(size));/* for the integer size size */
		bufsize += nbytes(size);        /* for the integer payload size */
		bufsize += size;                /* for the integer payload data */
	}
	size = nbytes(bufsize);
	plsize = bufsize;
	bufsize++;                              /* for the sequence header */
	bufsize += nbytes(size);                /* for the sequence size size */
	bufsize += size;                        /* for the sequence payload size */
	if ((buf = calloc(bufsize, sizeof(*buf))) == NULL) {
		ret = -1;
		goto error;
	}

	/* fill buffer */
	p = buf;
	*(p++) = SEQUENCE;                      /* sequence type */
	*(p++) = nbytes(plsize) | 0x80;         /* sequence size size */
	while (plsize > 0) {                    /* sequence payload size */
		*(p++) = plsize & 0xFF;
		plsize >>= CHAR_BIT;
	}
	for (i = 0; i < nnums; i++) {
		size = n = bignum_siz(nums[i]);
		*(p++) = INTEGER;               /* integer type */
		*(p++) = nbytes(size) | 0x80;   /* integer size size */
		while (n > 0) {                 /* integer payload size */
			*(p++) = n & 0xFF;
			n >>= CHAR_BIT;
		}
		bignum_write(nums[i], p, size); /* integer payload data */
		p += size;
	}

	/* print buffer converted into base64 */
	fprintf(fp, "-----BEGIN RSA PUBLIC KEY-----");
	for (i = 0; i < bufsize; i += 3) {
		if (i % 48 == 0)
			fprintf(fp, "\n");
		u = 0;
		n = 0;
		if (i + 0 < bufsize)
			u |= ((uint32_t)buf[i + 0]) << (2 * CHAR_BIT);
		if (i + 1 < bufsize)
			u |= ((uint32_t)buf[i + 1]) << (1 * CHAR_BIT);
		if (i + 2 < bufsize)
			u |= ((uint32_t)buf[i + 2]) << (0 * CHAR_BIT);
		fprintf(fp, "%c", base64alpha[(u >> (3 * 6) & 0x3F)]);
		fprintf(fp, "%c", base64alpha[(u >> (2 * 6) & 0x3F)]);
		if (i + 1 < bufsize) {
			fprintf(fp, "%c", base64alpha[(u >> (1 * 6) & 0x3F)]);
		} else {
			fprintf(fp, "=");
		}
		if (i + 2 < bufsize) {
			fprintf(fp, "%c", base64alpha[(u >> (0 * 6) & 0x3F)]);
		} else {
			fprintf(fp, "=");
		}
	}
	if (i % 48 != 0)
		fprintf(fp, "\n");
	fprintf(fp, "-----END RSA PUBLIC KEY-----\n");
error:
	free(buf);
	return ret;
}
