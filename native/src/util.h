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

static inline void clear_timerfd(int timer_fd) {
  // We need to read the number of timer expirations from the timer_fd to make it shut up.
  uint64_t time_read;
  if (read(timer_fd, &time_read, sizeof(time_read)) < 0) {
    printf("Cannot clear the timer\n");
  }
}

#endif
