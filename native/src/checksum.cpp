#include <arpa/inet.h>
#include <stdint.h>
// Cribbed from OpenBSD

uint32_t checksum(unsigned char *buf, uint32_t nbytes, uint32_t sum) {
    unsigned int i;

    /* Checksum all the pairs of bytes first. */
    for (i = 0; i < (nbytes & ~1U); i += 2) {
        sum += (uint16_t) ntohs(*((uint16_t *) (buf + i)));
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }

    /*
     * If there's a single byte left over, checksum it, too.
     * Network byte order is big-endian, so the remaining byte is
     * the high byte.
     */
    if (i < nbytes) {
        sum += buf[i] << 8;
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }

    return sum;
}

uint32_t wrapsum(uint32_t sum) {
    sum = ~sum & 0xFFFF;
    return htons(sum);
}
