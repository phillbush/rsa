#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bignum.h"
#include "sha.h"

#define SHA256_NROUNDS  64
#define SHA256_CTXLEN   8

#define E_COULDNOTREAD  "could not read message to hash"

static uint8_t inittab[SHA256_DIGEST] = {
	0x6a, 0x09, 0xe6, 0x67,
	0xbb, 0x67, 0xae, 0x85,
	0x3c, 0x6e, 0xf3, 0x72,
	0xa5, 0x4f, 0xf5, 0x3a,
	0x51, 0x0e, 0x52, 0x7f,
	0x9b, 0x05, 0x68, 0x8c,
	0x1f, 0x83, 0xd9, 0xab,
	0x5b, 0xe0, 0xcd, 0x19,
};

static SHA256_t roundconsts[SHA256_NROUNDS] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
	0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
	0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
	0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
	0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
	0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
	0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
	0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
	0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static SHA256_t
rrot(SHA256_t b, size_t n)
{
	return (b << (SHA256_T_SIZE * CHAR_BIT - n)) | (b >> n);
}

static void
shaprocess(SHA256_t ctx[SHA256_CTXLEN], uint8_t buf[SHA256_CHUNK])
{
	SHA256_t h[SHA256_CTXLEN];
	SHA256_t w[SHA256_NROUNDS];
	SHA256_t s0, s1, ch, maj;
	uint64_t tmp1, tmp2;
	size_t i, j;

	for (i = 0; i < SHA256_CHUNK / SHA256_T_SIZE; i++) {
		w[i] = 0;
		for (j = 0; j < SHA256_T_SIZE; j++) {
			w[i] <<= CHAR_BIT;
			w[i] |= buf[i * SHA256_T_SIZE + j];
		}
	}
	for (; i < SHA256_NROUNDS; i++) {
		s0 = rrot(w[i-15],  7) ^ rrot(w[i-15], 18) ^ (w[i-15] >>  3);
		s1 = rrot(w[i-2], 17) ^ rrot(w[i-2], 19) ^ (w[i-2] >> 10);
		tmp1 = w[i-16] + s0 + w[i-7] + s1;
		w[i] = tmp1 & SHA256_T_MAX;
	}
	memcpy(h, ctx, SHA256_CTXLEN * sizeof(*h));
	for (i = 0; i < SHA256_NROUNDS; i++) {
		s1 = rrot(h[4], 6) ^ rrot(h[4], 11) ^ rrot(h[4], 25);
		ch = (h[4] & h[5]) ^ (~(h[4]) & h[6]);
		tmp1 = h[7] + s1 + ch + roundconsts[i] + w[i];
		s0 = rrot(h[0], 2) ^ rrot(h[0], 13) ^ rrot(h[0], 22);
		maj = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
		tmp2 = s0 + maj;

		tmp2 += tmp1;
		tmp1 += h[3];
		h[7] = h[6];
		h[6] = h[5];
		h[5] = h[4];
		h[4] = tmp1 & SHA256_T_MAX;
		h[3] = h[2];
		h[2] = h[1];
		h[1] = h[0];
		h[0] = tmp2 & SHA256_T_MAX;
	}
	for (i = 0; i < SHA256_CTXLEN; i++) {
		tmp1 = ctx[i] + h[i];
		ctx[i] = tmp1 & SHA256_T_MAX;
	}
}

static void
shainit(uint8_t digest[SHA256_DIGEST])
{
	memcpy(digest, inittab, SHA256_DIGEST);
}

static void
shaproc(uint8_t digest[SHA256_DIGEST], uint8_t chunk[SHA256_CHUNK], uint64_t size, uint64_t chunksize)
{
	SHA256_t h[SHA256_CTXLEN];
	uint64_t i, j, k;
	uint8_t buf[SHA256_CHUNK] = { 0 };

	size *= CHAR_BIT;
	if (chunksize > SHA256_CHUNK)
		return;
	for (i = 0; i < SHA256_CTXLEN; i++) {
		h[i] = 0;
		for (j = 0; j < SHA256_T_SIZE; j++) {
			h[i] <<= CHAR_BIT;
			h[i] |= digest[i * SHA256_T_SIZE + j];
		}
	}
	if (chunksize < SHA256_CHUNK) {
		memcpy(buf, chunk, chunksize);
		buf[chunksize] = 0x80;
		k = size + 1 + 64;
		k = (SHA256_CHUNK * CHAR_BIT) - (k % (SHA256_CHUNK * CHAR_BIT));
		if (chunksize + (k + 1 + 64) / CHAR_BIT > SHA256_CHUNK) {
			shaprocess(h, buf);
			memset(buf, 0, SHA256_CHUNK);
		}
		i = SHA256_CHUNK;
		for (; size > 0; size >>= CHAR_BIT)
			buf[--i] = size & 0xFF;
		shaprocess(h, buf);
	} else {
		shaprocess(h, chunk);
	}
	for (i = 0; i < SHA256_CTXLEN; i++) {
		for (j = SHA256_T_SIZE; j > 0; j--) {
			digest[i * SHA256_T_SIZE + j - 1] = h[i] & 0xFF;
			h[i] >>= CHAR_BIT;
		}
	}
}

int
sharead(FILE *finp, uint8_t digest[SHA256_DIGEST], char **errstr)
{
	uint8_t chunk[SHA256_CHUNK];
	size_t fullsize, chunksize;

	*errstr = NULL;
	fullsize = 0;
	shainit(digest);
	while ((chunksize = fread(chunk, 1, SHA256_CHUNK, finp)) == SHA256_CHUNK) {
		shaproc(digest, chunk, fullsize, chunksize);
		fullsize += chunksize;
	}
	if (ferror(finp)) {
		*errstr = E_COULDNOTREAD;
		return -1;
	}
	fullsize += chunksize;
	shaproc(digest, chunk, fullsize, chunksize);
	return 0;
}

void
shaparse(uint8_t digest[SHA256_DIGEST], uint8_t *buf, size_t bufsize)
{
	size_t n;

	shainit(digest);
	for (n = bufsize; n > SHA256_CHUNK; n -= SHA256_CHUNK) {
		shaproc(digest, buf, bufsize, SHA256_CHUNK);
		buf += SHA256_CHUNK;
	}
	shaproc(digest, buf, bufsize, n);
}
