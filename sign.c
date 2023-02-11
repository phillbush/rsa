#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __linux__
#include <bsd/stdlib.h>
#endif

#include "bignum.h"
#include "sha.h"
#include "keyio.h"
#include "oaep.h"

#define DEF_RNDSIZE     (FIXNUM_SIZE * 3)
#define E_KEYTOOSHORT   "key modulus too short"

static void
usage(void)
{
	(void)fprintf(stderr, "usage: %s key message >sigfile\n", getprogname());
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	setprogname(argv[0]);
	argc--;
	argv++;
	if (argc != 2) {
		usage();
		return EXIT_FAILURE;
	}
	sign(argv[0], argv[1], stdout);
	return EXIT_SUCCESS;
}
