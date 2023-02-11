#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <bsd/stdlib.h>
#endif

#include "bignum.h"
#include "keyio.h"

#define DEF_VERS        0x00
#define DEF_BITS        1024
#define MIN_BITS        64
#define MAX_BITS        4096
#define DIG_SIZE        64
#define SDIG_BITS       "32"
#define DEF_EVAL        0x10001

static void
usage(void)
{
	(void)fprintf(stderr, "usage: %s [-d] [bits]\n", getprogname());
	exit(EXIT_FAILURE);
}

static int
genprime(Bignum *num, Bignum *minus1, Bignum *prev, Bignum *e, int nbits)
{
	Bignum q, r;
	uint64_t i;

	for (i = 0; i < 3U * (nbits * nbits); i++) {
		bignum_rndprime(nbits / CHAR_BIT, num);
		bignum_subshort(num, 1, minus1);
		bignum_div(minus1, e, &q, &r);
		if (bignum_cmp(prev, num) == 0)
			continue;
		if (bignum_iszero(&r))
			continue;
		if (bignum_isprime(num)) {
			return 0;
		}
	}
	return -1;
}

static void
genkey(int nbits)
{
	Bignum vers, p, q, p1, q1, n, e, d, f;
	Bignum *nums[ASN1_LAST];

	bignum_set(DEF_VERS, &vers);
	bignum_set(DEF_EVAL, &e);
	bignum_set(0, &p);
	if (genprime(&p, &p1, &e, &e, nbits) == -1)
		goto error;
	fprintf(stderr, ".");
	fflush(stderr);
	if (genprime(&q, &q1, &p, &e, nbits) == -1)
		goto error;
	fprintf(stderr, ".");
	fflush(stderr);
	bignum_mul(&p, &q, &n);
	bignum_mul(&p1, &q1, &f);
	bignum_invermod(&e, &f, &d);
	bignum_div(&d, &p1, &f, &p1);
	bignum_div(&d, &q1, &f, &q1);
	bignum_invermod(&q, &p, &f);
	fprintf(stderr, ".\n");
	fflush(stderr);
	nums[ASN1_VERS] = &vers;        /* version */
	nums[ASN1_N]    = &n;           /* n = q * p */
	nums[ASN1_E]    = &e;           /* e = DEF_EVAL */
	nums[ASN1_D]    = &d;           /* d = e^-1 mod phi */
	nums[ASN1_P]    = &p;           /* p = rand */
	nums[ASN1_Q]    = &q;           /* q = rand */
	nums[ASN1_DP]   = &p1;          /* d % (p-1) */
	nums[ASN1_DQ]   = &q1;          /* d % (q-1) */
	nums[ASN1_Q1]   = &f;           /* q^-1 mod p */
	fprintf(stdout, "-----BEGIN RSA PRIVATE KEY-----\n");
	keywrite(stdout, nums, ASN1_LAST);
	fprintf(stdout, "-----END RSA PRIVATE KEY-----\n");
	return;
error:
	errx(EXIT_FAILURE, "could not generate key pair");
}

int
main(int argc, char *argv[])
{
	int nbits;
	const char *errstr;

	setprogname(argv[0]);
	nbits = DEF_BITS;
	argc -= optind;
	argv += optind;
	switch (argc) {
	case 0:
		break;
	case 1:
		nbits = strtonum(*argv, MIN_BITS, MAX_BITS, &errstr);
		if (errstr != NULL)
			errx(1, "%s: %s", *argv, errstr);
		if (nbits % DIG_SIZE != 0)
			errx(1, "%s: not divisible by " SDIG_BITS, *argv);
		break;
	default:
		usage();
		return EXIT_FAILURE;
	}
	nbits /= 2;
	genkey(nbits);
	return EXIT_SUCCESS;
}
