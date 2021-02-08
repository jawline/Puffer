#ifndef SECURITYWALL_SOCKET_H
#define SECURITYWALL_SOCKET_H
#include <cstdint>
#include <cstdlib>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

class Socket {
public:
    Socket(int fd, sockaddr_in src, sockaddr_in dst, uint8_t proto) {
        this->fd = fd;
        this->src = src;
        this->dst = dst;
        this->proto = proto;
        clock_gettime(CLOCK_MONOTONIC, &last_use);
    }
    ~Socket() {
      if (fd >= 0) {
        close(fd);
        fd = -1;
      }
    }

    int fd;

    sockaddr_in src;
    sockaddr_in dst;

    uint8_t proto;
    struct timespec last_use;

    virtual bool on_tun(int tun_fd, char* ip, char* proto, char* data, size_t data_size, struct stats& stats) = 0;
    virtual void on_data(int tun_fd, char* data, size_t data_size, struct stats& stats) = 0;
    virtual void on_sock(int tun_fd, int events, struct stats& stats) = 0;
};

#endif
