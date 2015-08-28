
#include "/usr/include/stdint.h"

int RAND_bytes(unsigned char *buf, int num);
size_t strlcpy(char *dst, const char *src, size_t n);
size_t strlcat(char *dst, const char *src, size_t n);
void explicit_bzero(void *buf, size_t len);

#define arc4random_buf(a,b) RAND_bytes(a,b)

