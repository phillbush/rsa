RSA(6) - Games Manual

# NAME

**genrsa**,
**pubout**,
**asn1parse**,
**encrypt**,
**decrypt** - RSA utilities

# SYNOPSIS

**genrsa**
\[*nbits*]
\[*&gt;rsa.key*]  
**pubout**
\[*&lt;rsa.key*]
\[*&gt;rsa.pub*]  
**asn1parse**
\[*&lt;key*]  
**encrypt&nbsp;key**  
**decrypt&nbsp;key**

# DESCRIPTION

The
**genrsa**
utility generates an RSA private key,
which essentially involves the generation of two prime numbers.
The generated private key, along with other information,
is written into the standard output and encoded into PEM + ASN.1 format,
containing the following data:

*	The version (hardcoded to
	"0").

*	The composite modulus, N.

*	The public value, e.

*	The private value, d.

*	The private value, d.

*	The first prime factor of N, p.

*	The second prime factor of N, p.

*	The first exponent, d % (p - 1).

*	The second exponent, d % (q - 1).

*	The coefficient, q^-1 mod p.

The
**pubout**
utility extracts the public key (N and e) out of the private key.
The extracted public key is written into standard output.
The private key is read from standard input.

The
**asn1parse**
utility parses a private or public key created with the
**genrsa**
or
**pubout**
utilities.

The
**encrypt**
utility
is TODO.

The
**decrypt**
utility
is TODO.

# EXAMPLES

Generate a 128-bit private key into
*key*
and extract the public key into
*key.pub*:

	$ genrsa 128 | tee rsa.key | pubout >rsa.pub

Check the structure of a 128-bit private key:

	$ genrsa 128 | asn1parse

# SEE ALSO

openssl(1)

The following books were used during the development of these utilities:

Jonathan Katz,
Yehuda Lindell,
*Introduction to Modern Cryptography*,
*CRC Press*,
2021\.

Donald E. Knuth,
*The Art of Computer Programming*,
*Addison Wesley Longman*,
2,
1998\.

# HISTORY

These RSA utilities are the product of a project for 2022 2nd semester's course
of Cyber Security of the Computer Science department
of the University of Brasilia, Brazil.

# BUGS

The
**bignum.o**
module was written from scratch and is probably buggy;
i should have used an already existant arbitrary-precision arithmetic library.

Generating keys can take long time,
especially for 1024 bits or more.

OpenBSD 7.2 - February 9, 2023
