RSA(6) - Games Manual

# NAME

**genrsa**,
**pubout**,
**encrypt**,
**decrypt** - RSA utilities

# SYNOPSIS

**keygen**
\[*nbits*]  
**pubout**  
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
utility
is TODO.

The
**encrypt**
utility
is TODO.

The
**decrypt**
utility
is TODO.

# EXIT STATUS

The **genrsa** utility exits&#160;0 on success, and&#160;&gt;0 if an error occurs.

# EXAMPLES

Generate a 128-bit private key into
*key*
and extract the public key into
*key.pub*:

	$ genrsa 128 | tee key | pubout >key.pub

Check the structure of a 128-bit private key (requires OpenSSL):

	$ genrsa 128 | openssl asn1parse

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

The
**genrsa**,
**pubout**,
**encrypt**,
**decrypt**
RSA
utilities are the product of a project for 2022 2nd semester's course
of Cyber Security of the Computer Science department
of the University of Brasilia, Brazil.

# BUGS

The
**bignum.o**
module was written from scratch and is probably buggy;
i should have used an already existant arbitrary-precision arithmetic library.

Generating keys can take long time,
especially for 256 bits or more.

OpenBSD 7.2 - February 9, 2023
