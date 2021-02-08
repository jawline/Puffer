#ifndef SECURITYWALL_NETWORK_H
#define SECURITYWALL_NETWORK_H

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
