#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __linux__
#include <bsd/stdlib.h>
#endif

#include "bignum.h"
#include "keyio.h"

static void
usage(void)
{
	(void)fprintf(stderr, "usage: %s <rsa.key >rsa.pub\n", getprogname());
	exit(EXIT_FAILURE);
}

static void
pubout(FILE *finp, FILE *foutp)
{
	Bignum tmp, n, e;
	Bignum *priv[ASN1_LAST];
	Bignum *pub[2];
	size_t nnums, i;
	char *errstr;

	nnums = ASN1_LAST;
	errstr = NULL;
	for (i = 0; i < ASN1_LAST; i++)
		priv[i] = &tmp;
	priv[ASN1_N] = &n;
	priv[ASN1_E] = &e;
	if (keyread(finp, priv, nnums, &errstr) == -1)
		errx(EXIT_FAILURE, "%s", errstr);
	pub[0] = priv[ASN1_N];
	pub[1] = priv[ASN1_E];
	fprintf(foutp, "-----BEGIN RSA PUBLIC KEY-----\n");
	keywrite(foutp, pub, 2);
	fprintf(foutp, "-----END RSA PUBLIC KEY-----\n");
}

int
main(int argc, char *argv[])
{
	setprogname(argv[0]);
	argc -= optind;
	argv += optind;
	if (argc != 0) {
		usage();
		return EXIT_FAILURE;
	}
	pubout(stdin, stdout);
	return EXIT_SUCCESS;
}
