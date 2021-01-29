#ifndef _UTIL
#define _UTIL

void set_nonblocking(int fd) {
  int flags = fatal_guard(fcntl(fd, F_GETFL));
  fatal_guard(fcntl(fd, F_SETFL, flags | O_NONBLOCK));
}

void listen_epollin(int epoll_fd, int fd) {
  struct epoll_event event = { 0 };

  event.events = EPOLLIN;
  event.data.fd = fd;
 
  fatal_guard(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event));
}

#endif
