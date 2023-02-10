#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "bignum.h"
#include "keyio.h"

#define BASE64_ALPHASIZE        64
#define BASE64_BYTES            3
#define BASE64_CHARS            4
#define BASE64_SHIFT            6
#define COMMENT_CHAR            '-'
#define ERROR_ALLOC             "allocation error"
#define ERROR_TOOMANYINT        "too many values in asn.1 sequence"
#define ERROR_FERROR            "error reading input stream"
#define ERROR_EOF               "unnexpected end of file"
#define ERROR_HEADER            "unknown type header"
#define ERROR_NOSIZE            "zero size header"
#define ERROR_HALFSIZE          "incomplete size header"
#define ERROR_UNKNOWN           "read non-base64 character"
#define INDEX_UPPER             0
#define INDEX_LOWER             26
#define INDEX_NUMBER            (26+26)
#define INDEX_PLUS              (26+26+10)
#define INDEX_BAR               (26+26+10+1)

enum {
	SEQUENCE = 0x30,
	INTEGER  = 0x02,
};

struct Parse {
	FILE *fp;
	size_t nreadbytes, index;
	int goteof;
	uint8_t buf[BASE64_BYTES];
	char **errstr;
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
	plsize = bufsize;
	size = nbytes(bufsize);
	bufsize++;                              /* for the sequence header */
	bufsize += nbytes(size);                /* for the sequence size size */
	bufsize += size;                        /* for the sequence payload size */
	if ((buf = calloc(bufsize, sizeof(*buf))) == NULL) {
		ret = -1;
		goto error;
	}

	/* fill buffer */
	p = buf;
	n = nbytes(plsize);
	*(p++) = SEQUENCE;                      /* sequence type */
	*(p++) = n | 0x80;                      /* sequence size size */
	while (n > 0)                           /* sequence payload size */
		*(p++) = plsize >> ((--n) * CHAR_BIT);
	for (i = 0; i < nnums; i++) {
		size = bignum_siz(nums[i]);
		n = nbytes(size);
		*(p++) = INTEGER;               /* integer type */
		*(p++) = n | 0x80;              /* integer size size */
		while (n > 0)                   /* integer payload size */
			*(p++) = size >> ((--n) * CHAR_BIT);
		bignum_write(nums[i], p, size); /* integer payload data */
		p += size;
	}

	/* print buffer converted into base64 */
	for (i = 0; i < bufsize; i += 3) {
		if (i > 0 && i % 48 == 0)
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
error:
	free(buf);
	return ret;
}

static char *
checkferror(FILE *fp)
{
	if (ferror(fp))
		return ERROR_FERROR;
	return ERROR_EOF;
}

static int
getcomment(struct Parse *parse)
{
	int c;

	c = fgetc(parse->fp);
	if (c == EOF && ferror(parse->fp)) {
		*parse->errstr = ERROR_EOF;
		return -1;
	}
	if (c != COMMENT_CHAR) {
		ungetc(c, parse->fp);
		return 0;
	}
	while ((c = fgetc(parse->fp)) != EOF && c != '\n')
		;
	return 0;
}

static int
getcharbits(int c, uint8_t *u)
{
	*u = 0;
	if (c >= 'A' && c <= 'Z')
		*u = c - 'A' + INDEX_UPPER;
	else if (c >= 'a' && c <= 'z')
		*u = c - 'a' + INDEX_LOWER;
	else if (c >= '0' && c <= '9')
		*u = c - '0' + INDEX_NUMBER;
	else if (c == '+')
		*u = INDEX_PLUS;
	else if (c == '/')
		*u = INDEX_BAR;
	else if (c != '=')
		return -1;
	return 0;
}

static int
getbyte(struct Parse *parse, uint8_t *ret)
{
	uint32_t base;
	uint8_t u;
	int i, c;

	if (parse->goteof)
		goto error0;
	if (parse->index == 0) {
		base = 0;
		for (i = 0; i < BASE64_CHARS; i++) {
			while ((c = fgetc(parse->fp)) == '\n')
				;
			if (c == EOF)
				goto error0;
			if (getcharbits(c, &u) == -1)
				goto error1;
			base <<= BASE64_SHIFT;
			base |= u;
		}
		for (i = BASE64_BYTES - 1; i >= 0; i--) {
			parse->buf[i] = base & 0xFF;
			base >>= CHAR_BIT;
		}
	}
	*ret = parse->buf[parse->index++];
	parse->index %= BASE64_BYTES;
	parse->nreadbytes++;
	return 0;
error0:
	parse->goteof = 1;
	*(parse->errstr) = checkferror(parse->fp);
	return -1;
error1:
	*(parse->errstr) = ERROR_UNKNOWN;
	return -1;
}

static int
getheader(struct Parse *parse, uint8_t type)
{
	uint8_t u;

	if (getbyte(parse, &u) == -1)
		return -1;
	if (u != type) {
		*(parse->errstr) = ERROR_HEADER;
		return -1;
	}
	return 0;
}

static int
getsize(struct Parse *parse, size_t *size)
{
	uint8_t u, i, sizesize;

	*size = 0;
	if (getbyte(parse, &sizesize) == -1)
		return -1;
	if (sizesize == 0x00 || sizesize == 0x80) {
		*parse->errstr = ERROR_NOSIZE;
		return -1;
	}
	if (!(sizesize & 0x80)) {
		*size = sizesize;
		return 0;
	}
	sizesize &= 0x7F;
	for (i = 0; i < sizesize; i++) {
		if (getbyte(parse, &u) == -1)
			return -1;
		*size <<= CHAR_BIT;
		*size |= u;
	}
	return 0;
}

int
keyparse(FILE *fp, Bignum *nums[], size_t nnums, char **errstr)
{
	Bignum num;
	struct Parse parse;
	uint8_t *buf = NULL;
	size_t nreadnums, i, intsize, bufsize;

	parse = (struct Parse){
		.fp = fp,
		.buf = { 0 },
		.nreadbytes = 0,
		.index = 0,
		.goteof = 0,
		.errstr = errstr,
	};
	if (getcomment(&parse) == -1)
		return -1;
	if (getheader(&parse, SEQUENCE) == -1)
		return -1;
	if (getsize(&parse, &bufsize) == -1)
		return -1;
	parse.nreadbytes = 0;
	nreadnums = 0;
	while (parse.nreadbytes < bufsize) {
		if (nnums > 0 && nnums < nreadnums) {
			*errstr = ERROR_TOOMANYINT;
			return -1;
		}
		if (getheader(&parse, INTEGER) == -1)
			return -1;
		if (getsize(&parse, &intsize) == -1)
			return -1;
		if ((buf = malloc(intsize)) == NULL) {
			*errstr = ERROR_ALLOC;
			return -1;
		}
		for (i = 0; i < intsize; i++)
			if (getbyte(&parse, buf+i) == -1)
				return -1;
		if (nums != NULL) {
			bignum_read(nums[nreadnums++], buf, intsize);
		} else {
			bignum_read(&num, buf, intsize);
			bignum_print(stdout, &num);
		}
		free(buf);
	}
	if (getcomment(&parse) == -1)
		return -1;
	return 0;
}

int
keyread(FILE *fp, Bignum *nums[], size_t nnums, char **errstr)
{
	if (nums == NULL || nnums == 0) {
		*errstr = ERROR_TOOMANYINT;
		return -1;
	}
	return keyparse(fp, nums, nnums, errstr);
}

int
keyprint(FILE *fp, char **errstr)
{
	return keyparse(fp, NULL, 0, errstr);
}
