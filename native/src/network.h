#ifndef SECURITYWALL_NETWORK_H
#define SECURITYWALL_NETWORK_H

#if defined(__ANDROID__)

#include <jni.h>

#endif

#include "block_list.h"
#include "log.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/tcp.h>
#include <map>
#include <memory>
#include <netinet/udp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

const static size_t MTU = 1500;
const static ssize_t MSS = 1350;
const static size_t MAX_READS_ITER = 10000;
const static size_t CLOSING_TIMEOUT = 10000;
const static size_t MAX_EVENTS = 200;
const static size_t IP_HEADER_MIN_SIZE = (5 << 2);
const static size_t UDP_NAT_TIMEOUT_SECONDS = 30;

struct ip {
#if defined(__LITTLE_ENDIAN_BITFIELD)
  uint8_t ihl : 4;
  uint8_t version : 4;
#else
  uint8_t version : 4;
  uint8_t ihl : 4;
#endif
  uint8_t tos;
  uint16_t len;
  uint16_t id;
#if defined(__LITTLE_ENDIAN_BITFIELD)
  uint16_t flags : 3;
  uint16_t frag_offset : 13;
#else
  uint16_t frag_offset : 13;
  uint16_t flags : 3;
#endif
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
    return ip == o.ip && src_port == o.src_port && dst_port == o.dst_port &&
           proto == o.proto;
  }

  // Impl comparison to allow use in a map
  bool operator<(const ip_port_protocol &o) const {
#define CHECK_GUARD(a, b)                                                      \
  if (a < b) {                                                                 \
    return true;                                                               \
  }                                                                            \
  if (a > b) {                                                                 \
    return false;                                                              \
  }
    CHECK_GUARD(ip, o.ip);
    CHECK_GUARD(src_port, o.src_port);
    CHECK_GUARD(dst_port, o.dst_port);
    CHECK_GUARD(proto, o.proto);
#undef CHECK_GUARD
    return false;
  }
};

struct stats {
  size_t blocked;

  size_t udp_total;
  size_t tcp_total;

  size_t udp_bytes_in;
  size_t tcp_bytes_in;

  size_t udp_bytes_out;
  size_t tcp_bytes_out;
};

#endif
