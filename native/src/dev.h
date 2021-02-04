#ifndef _DEV_
#define _DEV_
#include "general.h"

void binddev(event_loop_t &loop, int fd);
void report(event_loop_t &loop, int udp, int tcp, int expired);

#endif
