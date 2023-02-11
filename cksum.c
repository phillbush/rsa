#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __linux__
#include <bsd/stdlib.h>
#endif

#include "bignum.h"
#include "sha.h"

static void
usage(void)
{
	(void)fprintf(stderr, "usage: %s <file\n", getprogname());
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	size_t i;
	uint8_t digest[SHA256_DIGEST];
	char *errstr;

	setprogname(argv[0]);
	argc--;
	argv++;
	if (argc != 0) {
		usage();
		return EXIT_FAILURE;
	}
	if (sharead(stdin, digest, &errstr) == -1)
		errx(EXIT_FAILURE, "%s", errstr);
	for (i = 0; i < SHA256_DIGEST; i++)
		if (printf("%02x", digest[i]) < 0)
			errx(EXIT_FAILURE, NULL);
	if (printf("\n") < 0)
		errx(EXIT_FAILURE, NULL);
	return EXIT_SUCCESS;
}
