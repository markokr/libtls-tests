
#include "/usr/include/stdint.h"

#include <sys/types.h>

int RAND_bytes(unsigned char *buf, int num);
size_t strlcpy(char *dst, const char *src, size_t n);
size_t strlcat(char *dst, const char *src, size_t n);
void explicit_bzero(void *buf, size_t len);

#define arc4random_buf(a,b) RAND_bytes(a,b)

//#define reallocarray(p, a, b) realloc(p, (a) * (b))
void *reallocarray(void *optr, size_t nmemb, size_t size);

#define X509_V_FLAG_NO_CHECK_TIME 0
