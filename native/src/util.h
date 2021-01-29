#ifndef _UTIL
#define _UTIL

static inline void set_nonblocking(int fd) {
  int flags = fatal_guard(fcntl(fd, F_GETFL));
  fatal_guard(fcntl(fd, F_SETFL, flags | O_NONBLOCK));
}

static inline void listen_epollin(int epoll_fd, int fd) {
  struct epoll_event event = { 0 };

  event.events = EPOLLIN;
  event.data.fd = fd;
 
  fatal_guard(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event));
}

static inline void initial_listen_tcp(int epoll_fd, int fd) {
  struct epoll_event event = { 0 };

  event.events = EPOLLOUT | EPOLLHUP;
  event.data.fd = fd;
 
  fatal_guard(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event));
}

static inline void listen_tcp(int epoll_fd, int fd) {
  struct epoll_event event = { 0 };

  event.events = EPOLLIN | EPOLLHUP;
  event.data.fd = fd;
 
  fatal_guard(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event));
}

static inline void stop_listen(int epoll_fd, int fd) {
  fatal_guard(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr));
}

static inline void clear_timerfd(int timer_fd) {
  // We need to read the number of timer expirations from the timer_fd to make it shut up.
  uint64_t time_read;
  if (read(timer_fd, &time_read, sizeof(time_read)) < 0) {
    printf("Cannot clear the timer\n");
  }
}

static inline sockaddr_in lookup_dst_udp(ip* hdr, udphdr* udp_hdr) {
  struct sockaddr_in dst = { 0 };
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = hdr->daddr;
  dst.sin_port = udp_hdr->uh_dport;
  return dst;
}

static inline sockaddr_in lookup_dst_tcp(ip* hdr, tcphdr* tcp_hdr) {
  struct sockaddr_in dst = { 0 };
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = hdr->daddr;
  dst.sin_port = tcp_hdr->dest;
  return dst;
}

#endif
