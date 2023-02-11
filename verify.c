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

static void
usage(void)
{
	(void)fprintf(stderr, "usage: %s key message <sigfile\n", getprogname());
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
	if (verify(argv[0], argv[1], stdin))
		return EXIT_SUCCESS;
	fprintf(stderr, "verification failed\n");
	return EXIT_FAILURE;
}
