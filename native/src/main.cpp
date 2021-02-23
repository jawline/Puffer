#include "checksum.h"
#include "core.h"
#include "log.h"
#include "packet.h"
#include "tcp.h"
#include "tls.h"
#include "tun.h"
#include "udp.h"
#include "util.h"
#include <arpa/inet.h>
#include <sys/timerfd.h>

#ifndef __ANDROID__
int main() {

  debug("Manifest piping");
  int fds[2];
  fatal_guard(pipe(fds));

  debug("Creating TESTTUN");
  int tunfd = tun_alloc("blaketest", IFF_TUN | IFF_NO_PI);

  debug("Loading block list");
  FILE *blist = fopen("lists/base.txt", "r");
  FILE *alist = fopen("lists/allow.txt", "r");
  BlockList b(blist, alist);

  debug("Creating event loop");
  EventLoop loop(tunfd, fds[0], 2, b);
  loop.user_space_ip_proxy();
}
#endif
