#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <bsd/stdlib.h>
#endif

#include "bignum.h"
#include "sha.h"
#include "keyio.h"

#define DEF_RNDSIZE     (FIXNUM_SIZE * 3)
#define MIN(a, b)       ((a) < (b) ? (a) : (b))

static void
oaepencode(uint8_t *msg, size_t modsize, size_t msgsize)
{
	uint8_t hash[SHA256_DIGEST];
	uint8_t rnd[DEF_RNDSIZE];
	size_t headsize, padsize, minsize, i;

	/* msg is modsize bytes long, with the first msgsize byte filled */
	padsize = modsize - DEF_RNDSIZE - msgsize;
	headsize = msgsize + padsize;
	memset(msg + msgsize, 0, padsize);      /* pad zeroes to message */
	arc4random_buf(rnd, DEF_RNDSIZE);           /* write random bytes into tail */

	/* hash(rnd) ^ msg */
	shaparse(hash, rnd, DEF_RNDSIZE);       /* generate head as XOR of rnd and */
	minsize = MIN(headsize, SHA256_DIGEST);
	for (i = 0; i < minsize; i++)
		msg[i] = msg[i] ^ hash[i];

	/* hash(hash(rnd) ^ msg) ^ rnd */
	shaparse(hash, msg, headsize);
	minsize = MIN(DEF_RNDSIZE, SHA256_DIGEST);
	for (i = 0; i < minsize; i++)
		rnd[i] = rnd[i] ^ hash[i];

	/* move bytes around */
	memmove(msg + DEF_RNDSIZE, msg, headsize);
	memcpy(msg, rnd, DEF_RNDSIZE);
}

static void
oaepdecode(uint8_t *msg, size_t modsize)
{
	uint8_t hash[SHA256_DIGEST];
	uint8_t rnd[DEF_RNDSIZE];
	size_t headsize, minsize, i;

	headsize = modsize - DEF_RNDSIZE;

	/* hash(tail) ^ head */
	shaparse(hash, msg + DEF_RNDSIZE, headsize);
	minsize = MIN(DEF_RNDSIZE, SHA256_DIGEST);
	for (i = 0; i < minsize; i++)
		rnd[i] = hash[i] ^ msg[i];

	/* hash(hash(tail) ^ head) ^ tail */
	shaparse(hash, rnd, DEF_RNDSIZE);
	minsize = MIN(headsize, SHA256_DIGEST);
	for (i = 0; i < minsize; i++)
		msg[i] = hash[i] ^ msg[DEF_RNDSIZE + i];
}

static void
parsekey(Bignum *mod, Bignum *exp, char *keyfile)
{
	FILE *fp;
	Bignum key[ASN1_LAST];
	Bignum *keyp[ASN1_LAST];
	int nnums, i;
	char *errstr;

	errstr = NULL;
	if ((fp = fopen(keyfile, "rb")) == NULL)
		err(EXIT_FAILURE, "%s", keyfile);
	for (i = 0; i < ASN1_LAST; i++)
		keyp[i] = &key[i];
	if ((nnums = keyread(fp, keyp, ASN1_LAST, &errstr)) == -1)
		errx(EXIT_FAILURE, "%s: %s", keyfile, errstr);
	switch (nnums) {
	case ASN1_LAST:
		/* private key */
		bignum_cpy(keyp[ASN1_N], mod);
		bignum_cpy(keyp[ASN1_D], exp);
		break;
	case 2:
		/* public key */
		bignum_cpy(keyp[0], mod);
		bignum_cpy(keyp[1], exp);
		break;
	default:
		errx(EXIT_FAILURE, "%s: unknown key format", keyfile);
		break;
	}
	fclose(fp);
}

static void
hashfile(uint8_t buf[SHA256_DIGEST /* or larger */], char *origfile)
{
	FILE *fp;
	char *errstr;

	if ((fp = fopen(origfile, "rb")) == NULL)
		err(EXIT_FAILURE, "%s", origfile);
	if (sharead(fp, buf, &errstr) == -1)
		errx(EXIT_FAILURE, "%s: %s", origfile, errstr);
	fclose(fp);
}

static void
getsig(FILE *finp, Bignum *sig)
{
	size_t i;
	uint8_t u;

	bignum_set(0, sig);
	for (i = 0; i < BIGNUM_MAXSIZE * FIXNUM_SIZE; i++) {
		if (fread(&u, 1, 1, finp) == 0)
			break;
		if (ferror(finp))
			err(EXIT_FAILURE, NULL);
		bignum_lsh(sig, CHAR_BIT, sig);
		bignum_addshort(sig, u, sig);
	}
	if (ferror(finp)) {
		err(EXIT_FAILURE, NULL);
	}
	if (!feof(finp) || i == BIGNUM_MAXSIZE * FIXNUM_SIZE) {
		errx(EXIT_FAILURE, "signature file too long");
	}
}

void
sign(char *keyfile, char *origfile, FILE *foutp)
{
	Bignum mod, exp, sig;
	size_t modsize;
	uint8_t *msg;

	parsekey(&mod, &exp, keyfile);
	modsize = bignum_size(&mod);
	if (modsize <= DEF_RNDSIZE + SHA256_DIGEST)
		errx(EXIT_FAILURE, "%s: key modulus too short", keyfile);
	if ((msg = malloc(modsize)) == NULL)
		err(EXIT_FAILURE, "malloc");
	hashfile(msg, origfile);
	oaepencode(msg, modsize, SHA256_DIGEST);
	bignum_read(&sig, msg, modsize);
	bignum_powermod(&sig, &exp, &mod, &sig);
	bignum_binprint(foutp, &sig);
	free(msg);
}

int
verify(char *keyfile, char *origfile, FILE *finp)
{
	Bignum mod, exp, sig;
	size_t modsize, sigsize, i;
	uint8_t hash[SHA256_DIGEST];
	uint8_t *buf;

	parsekey(&mod, &exp, keyfile);
	modsize = bignum_size(&mod);
	if (modsize <= DEF_RNDSIZE + SHA256_DIGEST)
		errx(EXIT_FAILURE, "%s: key modulus too short", keyfile);
	getsig(finp, &sig);
	bignum_powermod(&sig, &exp, &mod, &sig);
	sigsize = bignum_size(&sig);
	if (sigsize > modsize)
		return 0;
	if ((buf = malloc(sigsize)) == NULL)
		err(EXIT_FAILURE, "malloc");
	bignum_write(&sig, buf, sigsize);
	oaepdecode(buf, sigsize);
	hashfile(hash, origfile);
	for (i = 0; i < DEF_RNDSIZE; i++)
		if (buf[sigsize - i - 1] != 0)
			goto fail;
	for (i = 0; i < SHA256_DIGEST; i++)
		if (buf[i] != hash[i])
			goto fail;
	free(buf);
	return 1;
fail:
	free(buf);
	return 0;
}
