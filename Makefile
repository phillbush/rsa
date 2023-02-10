PROG = genrsa pubout asn1parse
OBJS = ${PROG:=.o} bignum.o keyio.o pubout.o asn1parse.o
SRCS = ${PROG:=.c}
DOCS = README.md README.pdf

DEFS = -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -D_BSD_SOURCE

all: ${PROG} ${DOCS}

genrsa: genrsa.o bignum.o keyio.o
	${CC} ${LDFLAGS} -o $@ genrsa.o bignum.o keyio.o

pubout: pubout.o bignum.o keyio.o
	${CC} ${LDFLAGS} -o $@ pubout.o bignum.o keyio.o

asn1parse: asn1parse.o bignum.o keyio.o
	${CC} ${LDFLAGS} -o $@ asn1parse.o bignum.o keyio.o

asn1parse.o :      keyio.h
genrsa.o: bignum.h keyio.h
pubout.o: bignum.h keyio.h
keyio.o:  bignum.h

.c.o:
	${CC} -std=c99 -pedantic ${DEFS} ${CFLAGS} ${CPPFLAGS} -c $<

README.md: rsa.6
	man -T markdown -l rsa.6 >README.md

README.pdf: rsa.6
	man -T pdf -l rsa.6 >README.pdf

tags: ${SRCS}
	ctags ${SRCS}

clean:
	rm -f ${OBJS} ${PROG} ${PROG:=.core} tags

.PHONY: all tags clean
