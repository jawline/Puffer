#ifndef _CHK
#define _CHK
#include <stdint.h>

uint32_t checksum(unsigned char *buf, uint32_t nbytes, uint32_t sum);
uint32_t wrapsum(uint32_t sum);

#endif
