#include "dev.h"

/// This function protects us from the VPN device
/// TODO: Figure out how to drive this from android (I think VpnBuilder can take care of it)
void binddev(int fd) {
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "wlp2s0");
  if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
    printf("Woof\n");
  }
} 
