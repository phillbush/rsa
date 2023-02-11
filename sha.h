#include <limits.h>
#include <stdint.h>

#define SHA256_DIGEST   (256 / CHAR_BIT)
#define SHA256_CHUNK    (SHA256_DIGEST * 2)
#define SHA256_T_SIZE   (sizeof(SHA256_t))
#define SHA256_T_MAX    UINT32_MAX

typedef uint32_t        SHA256_t;

/*
 * Hash data read from finp.
 * It can fail due to IO; returning -1 in such case.
 */
int sharead(FILE *finp, uint8_t digest[SHA256_DIGEST], char **errstr);

/*
 * Hash data in buf, which is at least bufsize.
 * Digest should be at least SHA256_DIGEST.
 * Undefined behavior will occur if either buffer is less than those
 * sizes.
 */
void shaparse(uint8_t digest[SHA256_DIGEST], uint8_t *buf, size_t bufsize);
