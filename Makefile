PROG = genrsa pubout asn1parse cksum sign verify
OBJS = ${PROG:=.o} bignum.o keyio.o sha.o oaep.o
SRCS = ${PROG:=.c}
DOCS = README README.pdf

DEFS = -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -D_BSD_SOURCE

all: ${PROG}

docs: ${DOCS}

sign: sign.o sha.o bignum.o keyio.o oaep.o
	${CC} ${LDFLAGS} -o $@ sign.o sha.o bignum.o keyio.o oaep.o

verify: verify.o sha.o bignum.o keyio.o oaep.o
	${CC} ${LDFLAGS} -o $@ verify.o sha.o bignum.o keyio.o oaep.o

genrsa: genrsa.o bignum.o keyio.o
	${CC} ${LDFLAGS} -o $@ genrsa.o bignum.o keyio.o

pubout: pubout.o bignum.o keyio.o
	${CC} ${LDFLAGS} -o $@ pubout.o bignum.o keyio.o

asn1parse: asn1parse.o bignum.o keyio.o
	${CC} ${LDFLAGS} -o $@ asn1parse.o bignum.o keyio.o

cksum: cksum.o sha.o
	${CC} ${LDFLAGS} -o $@ cksum.o sha.o bignum.o

sign:        bignum.h keyio.h oaep.h sha.h
verify:      bignum.h keyio.h oaep.h sha.h
genrsa.o:    bignum.h keyio.h
pubout.o:    bignum.h keyio.h
asn1parse.o: bignum.h keyio.h
keyio.o:     bignum.h
sha.o:       bignum.h sha.h
cksum.o:     bignum.h sha.h

.c.o:
	${CC} -std=c99 -pedantic ${DEFS} ${CFLAGS} ${CPPFLAGS} -c $<

README: rsa.6
	man -T ascii -l rsa.6 | col -b | expand >README

README.pdf: rsa.6
	man -T pdf -l rsa.6 >README.pdf

tags: ${SRCS}
	ctags ${SRCS}

clean:
	rm -f ${OBJS} ${PROG} ${PROG:=.core} tags

.PHONY: all tags clean
