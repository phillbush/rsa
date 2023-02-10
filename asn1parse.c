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
	(void)fprintf(stderr, "usage: %s <key\n", getprogname());
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	char *errstr;

	setprogname(argv[0]);
	argc -= optind;
	argv += optind;
	if (argc != 0) {
		usage();
		return EXIT_FAILURE;
	}
	if (keyprint(stdin, &errstr) == -1)
		errx(EXIT_FAILURE, "%s", errstr);
	return EXIT_SUCCESS;
}
