#include <stdint.h>

/*
 * This is an extremelly simple arbitrary-precision arithmetic
 * of unsigned integers.
 *
 * There's no dynamic allocation.
 *
 * The largest number we handle is 2^(512 * 32)-1.
 *
 * We do not handle errors, so we do lots of assumptions (like
 * assuming denominator is not zero and is less than numerator).
 *
 * I hope you have lots of memory :)
 *
 ***********************************************************************
 * !WARNING!   All functions that get a pointer to Bignum expect the   *
 *             pointer to be non NULL and point to the address of a    *
 *             valid big number!                                       *
 ***********************************************************************
 */

#define BIGNUM_MAXSIZE  512
#define FIXNUM_MAX      UINT32_MAX
#define FIXNUM_BASE     0x100000000
#define FIXNUM_SIZE     (sizeof(uint32_t))
#define FIXNUM_BIT      (FIXNUM_SIZE * CHAR_BIT)

typedef uint32_t Fixnum;
typedef uint64_t Tmpnum;
typedef struct Bignum Bignum;

struct Bignum {
	/* little-endian array of 32-bit digits */
	Fixnum data[BIGNUM_MAXSIZE];
	int size;
};

/*
 * Compare (*a) to (*b), returning -1, 0 or +1.
 */
int bignum_cmp(Bignum *a, Bignum *b);

/*
 * Set the value of bignum to n.
 */
void bignum_set(Tmpnum n, Bignum *res);

/*
 * Copy the data from (*src) to (*dst)
 */
void bignum_cpy(Bignum *src, Bignum *dst);

/*
 * Compute addition; (*res) = (*a) + (*b).
 *
 * bignum_addshort works the same, but b is a fixnum,
 * not a bignum.
 */
void bignum_add(Bignum *a, Bignum *b, Bignum *res);
void bignum_addshort(Bignum *a, Fixnum b, Bignum *res);

/*
 * Compute; subtraction; (*res) = (*a) - (*b).
 *
 * It assumes (*a) is greater than or equal to (*a);
 * undefined behavior WILL happen if that is false.
 *
 * bignum_subshort works the same, but b is a fixnum,
 * not a bignum.
 */
void bignum_sub(Bignum *a, Bignum *b, Bignum *res);
void bignum_subshort(Bignum *a, Fixnum b, Bignum *res);

/*
 * Compute multiplication; (*res) = (*a) * (*b).
 */
void bignum_mul(Bignum *a, Bignum *b, Bignum *res);

/*
 * Compute left shift; (*res) = (*a) << b.
 */
void bignum_lsh(Bignum *a, Fixnum b, Bignum *res);

/*
 * Compute right shift; (*res) = (*a) >> b.
 */
void bignum_rsh(Bignum *a, Fixnum b, Bignum *res);

/*
 * Compute division; (*a) = (*q) * (*b) + (*r).
 *
 * It assumes (*b) is not zero, and that (*b) is less
 * than or equal to (a); undefined behavior WILL happen
 * if that is false.
 */
void bignum_div(Bignum *a, Bignum *b, Bignum *q, Bignum *r);

/*
 * short division
 */
void bignum_divshort(Bignum *num, Fixnum div, Bignum *quo, Bignum *rem);

/*
 * Set (*res) to a random value of n bytes.
 */
void bignum_rnd(int n, Bignum *res);

/*
 * Set (*res) to a random prime candidate value of n bytes.
 *
 * The function rand must return a random 32-bit value.
 * The 2 most significant bits of the result are always 1.
 * (*res) is always odd.
 */
void bignum_rndprime(int n, Bignum *res);

/*
 * Apply Miller-Rabin primality test.
 */
int bignum_isprime(Bignum *num);

/*
 * Compute gcd; (*res) = gcd((*a), (*b)).
 */
void bignum_gcd(Bignum *a, Bignum *b, Bignum *res);

/*
 * Compute modular exponentiation; (*res) = (*b) ^ (e) mod (*m).
 *
 * "BIGNUM POWERMOD" is such a cool name; gonna use it as my irc nickname.
 */
void bignum_powermod(Bignum *b, Bignum *e, Bignum *m, Bignum *res);

/*
 * Compute modular multiplicative inverse; (*a)(*res) congr 1 mod (*m)
 *
 * It assumes (*a) and (*b) to be coprimes.
 */
void bignum_invermod(Bignum *a, Bignum *m, Bignum *res);

/*
 * Is zero?
 */
int bignum_iszero(Bignum *num);

/*
 * Write the bytes from (*num) into buf of size bufsize.
 */
int bignum_write(Bignum *num, unsigned char *buf, size_t bufsize);

/*
 * Read the bytes from buf of bufsize into (*num).
 */
void bignum_read(Bignum *num, unsigned char *buf, size_t bufsize);

/*
 * return number of bytes in (*num)
 */
size_t bignum_size(Bignum *num);

void bignum_print(FILE *fp, Bignum *num);
void bignum_binprint(FILE *fp, Bignum *num);
