PROG = genrsa
OBJS = ${PROG:=.o} bignum.o keyio.o
SRCS = ${PROG:=.c}
DOCS = README.md README.pdf

DEFS = -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -D_BSD_SOURCE

all: ${PROG} ${DOCS}

genrsa.o: bignum.h keyio.h
keyio.h:  bignum.h

genrsa: genrsa.o bignum.o keyio.o
	${CC} ${LDFLAGS} -o $@ genrsa.o bignum.o keyio.o

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
