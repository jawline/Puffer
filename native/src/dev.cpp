#include "dev.h"

/// This function protects us from the VPN device
/// TODO: Figure out how to drive this from android (I think VpnBuilder can take care of it)
void binddev(event_loop_t& loop, int fd) {
#if defined(__ANDROID__)
    jclass secc = (loop.env)->GetObjectClass(loop.swall);
    jmethodID protect = loop.env->GetMethodID(secc,"protect", "(I)V");
    (loop.env)->CallVoidMethod(loop.swall, protect, fd);
#else
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "wlp2s0");
  if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
    printf("Woof\n");
  }
#endif
}

void report(event_loop_t& loop, int udp, int tcp, int expired) {

    debug("STATE: UDP: %lu / %lu (%lu / %lu) bytes TCP: %lu / %lu (%lu / %lu) EXPIRED: %lu BLOCKED (THIS SESSION): %lu", udp, loop.stat.udp_total, loop.stat.udp_bytes_in, loop.stat.udp_bytes_out, tcp, loop.stat.tcp_total, loop.stat.tcp_bytes_in, loop.stat.tcp_bytes_out, expired, loop.stat.blocked);
#if defined(__ANDROID__)
    jclass secc = (loop.env)->GetObjectClass(loop.swall);
    jmethodID protect = loop.env->GetMethodID(secc,"report", "(JJJJJJJ)V");
    (loop.env)->CallVoidMethod(loop.swall, protect, (jlong) tcp, (jlong) loop.stat.tcp_total, (jlong) udp, (jlong) loop.stat.udp_total, (jlong) (loop.stat.tcp_bytes_in + loop.stat.udp_bytes_in), (jlong) (loop.stat.tcp_bytes_out + loop.stat.udp_bytes_out), (jlong) loop.stat.blocked);
#else

#endif
}
