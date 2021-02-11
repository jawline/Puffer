#ifndef _UTIL
#define _UTIL
#include "network.h"

static inline ssize_t tun_write(int tun_fd, char *pkt, size_t pkt_sz) {
  ssize_t r;

  while (true) {
    r = write(tun_fd, pkt, pkt_sz);
    if (r == -1) {
      if (errno == EAGAIN) {
        log("TCP: TUN Write blocked");
      } else {
        log("TCP: Tun write %i", errno);
      }
    } else {
      break;
    }
  }

  return r;
}

static inline void set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL);
  fatal_guard(flags);
  fatal_guard(fcntl(fd, F_SETFL, flags | O_NONBLOCK));
}

static inline void set_fast_tcp(int fd) {
  const int yes = 1;
  fatal_guard(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&yes, sizeof(yes)));
  fatal_guard(setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, (void *)&yes, sizeof(yes)));
}

static inline void listen_tcp(int epoll_fd, int fd) {
  struct epoll_event event = {0};

  event.events = EPOLLIN | EPOLLHUP | EPOLLRDHUP;
  event.data.fd = fd;

  fatal_guard(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event));
}

static inline void stop_listen(int epoll_fd, int fd) {
  fatal_guard(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr));
}

static inline void clear_timerfd(int timer_fd) {
  // We need to read the number of timer expirations from the timer_fd to make
  // it shut up.
  uint64_t time_read;
  if (read(timer_fd, &time_read, sizeof(time_read)) < 0) {
    printf("Cannot clear the timer\n");
  }
}

static inline sockaddr_in lookup_dst_udp(ip *hdr, udphdr *udp_hdr) {
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = hdr->daddr;
  dst.sin_port = udp_hdr->uh_dport;
  return dst;
}

static inline sockaddr_in lookup_dst_tcp(ip *hdr, tcphdr *tcp_hdr) {
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = hdr->daddr;
  dst.sin_port = tcp_hdr->dest;
  return dst;
}

static inline sockaddr_in generate_addr(uint32_t ip, uint16_t port) {
  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = ip;
  addr.sin_port = port;
  return addr;
}

#endif
