#ifndef _GR
#define _GR
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/tcp.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/epoll.h>
#include <map>
#include <netinet/udp.h>
#include <stdint.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>

#define MTU 1500
#define MAX_EVENTS 500

#define DROP_GUARD(e) if (!(e)) { \
  printf("Dropped Packet (%i) (DROP GUARD) %i\n", e, __LINE__); \
  perror("Reason: "); \
  return; \
}

#define DROP_GUARD_INT(e) if (!(e)) { \
  printf("Dropped Packet (%i) (DROP GUARD) %i\n", e, __LINE__); \
  perror("Reason: "); \
  return - 1; \
}

inline int fatal_guard(int r) {
  if (r < 0) {
    fprintf(stderr, "Guard was violated\n");
    exit(1);
  } else {
    return r;
  }
}

struct ip {
    uint8_t ihl : 4;
    uint8_t version : 4;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t flags : 3;
    uint16_t frag_offset : 13;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

struct ip_port_protocol {
  uint32_t ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t proto;

  bool operator==(const ip_port_protocol &o) const {
    return memcmp(this, &o, sizeof(*this)) == 0; 
  }

  // Impl comparison to allow use in a map
  bool operator<(const ip_port_protocol &o) const {
    return memcmp(this, &o, sizeof(*this)) < 0;
  }
};

struct tcp_state {
  uint32_t seq;
  uint32_t ack;
  bool connected;
};

struct msg_return {
  int fd;
  uint32_t src_ip;
  uint16_t src_port;
  uint8_t proto;
  struct timespec last_use;

  // Only set on TCP packets
  std::shared_ptr<tcp_state> state;
};

typedef struct event_loop {
  int tunnel_fd;
  int epoll_fd;
  int timer_fd;
  std::map<ip_port_protocol, msg_return> udp_pairs;
  std::map<int, msg_return> udp_return;
} event_loop_t;

#endif
