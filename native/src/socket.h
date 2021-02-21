#ifndef SECURITYWALL_SOCKET_H
#define SECURITYWALL_SOCKET_H

#include "block_list.h"
#include "tls.h"
#include <cstdint>
#include <cstdlib>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>

class Socket {
public:
  Socket(int fd, sockaddr_in src, sockaddr_in dst, uint8_t proto) {
    this->fd = fd;
    this->src = src;
    this->dst = dst;
    this->proto = proto;
    this->blocked = false;
    clock_gettime(CLOCK_MONOTONIC, &last_use);
    strcpy(stream_name, "N/A");
  }

  ~Socket() {
    if (fd >= 0) {
      debug("TCP %i: closing file descriptor", fd);
      close(fd);
      fd = -1;
    }
  }

  int fd;

  sockaddr_in src;
  sockaddr_in dst;

  char stream_name[MAX_FQDN_LENGTH];

  // Set to true if the reason the stream was terminated is due to a block
  bool blocked;

  uint8_t proto;
  struct timespec last_use;

  virtual bool on_tun(int tun_fd, int epoll_fd, char *ip, char *proto, char *data, size_t data_size, BlockList const &block, struct stats &stats,
                      timespec const &cur_time) = 0;

  virtual bool before_tun(int tun_fd, int epoll_fd) = 0;

  virtual bool after_tun(int tun_fd, int epoll_fd, timespec const &cur_time) = 0;

  virtual bool on_data(int tun_fd, int epoll_fd, char *data, size_t data_size, struct stats &stats, timespec const &cur_time) = 0;

  virtual bool on_sock(int tun_fd, int epoll_fd, int events, struct stats &stats, timespec const &cur_time) = 0;
};

#endif
