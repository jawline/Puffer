#include "general.h"
#include "checksum.h"
#include "tun.h"
#include "util.h"
#include "packet.h"
#include "log.h"
#include "tls.h"
#include <sys/timerfd.h>
#include <arpa/inet.h>
#include "udp.h"
#include "tcp.h"

int main() {

  debug("Manifest piping");
  int fds[2];
  fatal_guard(pipe(fds));

  debug("Creating TESTTUN");
  int tunfd = tun_alloc("blaketest", IFF_TUN | IFF_NO_PI);

  debug("Loading block list");
  FILE* blist = fopen("lists/base.txt", "r");
  BlockList b(blist);

  debug("Creating event loop");
  EventLoop loop(tunfd, fds[0], b);
  loop.user_space_ip_proxy();
}
