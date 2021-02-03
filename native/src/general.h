#ifndef _GR
#define _GR

#if defined(__ANDROID__)
#include <jni.h>
#endif

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
#include "log.h"
#include "block_list.h"

#define MTU 1500
#define MAX_EVENTS 500

#define MAX(a, b) ((a > b) ? a : b)

#define fatal_guard(r) \
  if (r < 0) { \
    debug("Guard violated"); \
    exit(1); \
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
  uint32_t them_seq;
  uint32_t them_ack;

  uint32_t us_seq;
  uint32_t us_ack;

  bool sent_syn_ack;
  bool recv_first_ack;

  bool close_wr;

  bool close_rd;
  bool ack_rd;

  bool first_packet;
};

struct msg_return {
  int fd;

  sockaddr_in src;
  sockaddr_in dst;

  uint8_t proto;
  struct timespec last_use;

  // Only set on TCP packets
  std::shared_ptr<tcp_state> state;
};

typedef struct event_loop {

  event_loop(BlockList const& list): block(list) {
    blocked = 0;
    udp_total = 0;
    tcp_total = 0;
    udp_bytes_in = 0;
    tcp_bytes_in = 0;
    udp_bytes_out = 0;
    tcp_bytes_out = 0;
    tunnel_fd = -1;
    epoll_fd = -1;
    timer_fd = -1;
  }

  size_t blocked;

  size_t udp_total;
  size_t tcp_total;

  size_t udp_bytes_in;
  size_t tcp_bytes_in;

  size_t udp_bytes_out;
  size_t tcp_bytes_out;

  int tunnel_fd;
  int epoll_fd;
  int quit_fd;
  int timer_fd;

  std::map<ip_port_protocol, msg_return> udp_pairs;
  std::map<int, msg_return> udp_return;

  BlockList block;

#if defined(__ANDROID__)
  JNIEnv *env;
  jobject swall;
#endif
} event_loop_t;

void user_space_ip_proxy(int tunnel_fd, event_loop_t loop);

#endif
