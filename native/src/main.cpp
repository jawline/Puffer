#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
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

int guard(int r) {
  if (r < 0) {
    fprintf(stderr, "Guard was violated\n");
    exit(1);
  } else {
    return r;
  }
} 

void set_nonblocking(int fd) {
  int flags = guard(fcntl(fd, F_GETFL));
  guard(fcntl(fd, F_SETFL, flags | O_NONBLOCK));
}

void listen_epollin(int epoll_fd, int fd) {
  struct epoll_event event = { 0 };

  event.events = EPOLLIN;
  event.data.fd = fd;
 
  guard(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event));
}

#define MTU 1500
#define MAX_EVENTS 500

#define DROP_GUARD(e) if (!e) { \
  printf("Dropped Packet (DROP GUARD)\n"); \
  return; \
}

struct ip {
    uint8_t version : 4;
    uint8_t ihl : 4;
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

struct ip_port {
  uint32_t ip;
  uint16_t port;

  // Impl comparison to allow use in a map
  bool operator<(const ip_port &o) const {
    if (this->ip == o.ip && this->port == o.port) {
      return 0;
    } else {
      return -1;
    }
  }
};

typedef struct event_loop {
  int epoll_fd;
  std::map<ip_port, int> udp_pairs;
} event_loop_t;

void process_packet_icmp(struct ip* hdr, char* bytes, size_t len) {
  // TODO it is possible to manually do ICMP sockets on Android
  // int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  // Only echo requests will work
  printf("Sorry - I cannot\n");
}

void process_packet_udp(event_loop_t* loop, struct ip* hdr, char* bytes, size_t len) {
  DROP_GUARD(len >= sizeof(struct udphdr));

  struct udphdr* udp_hdr = (struct udphdr *) bytes;
  struct ip_port id = { hdr->daddr, udp_hdr->uh_sport };

  auto fd_scan = loop->udp_pairs.find(id);

  int found_fd;

  if (fd_scan != loop->udp_pairs.end()) {
    found_fd = (*fd_scan).second;
  } else {
    // No known UDP socket, open a new one

    // Create a new UDP FD
    int new_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    DROP_GUARD(new_fd >= 0);

    // Register it
    loop->udp_pairs[id] = new_fd;
    listen_epollin(loop->epoll_fd, new_fd);
    set_nonblocking(new_fd);

    found_fd = new_fd;
  }

  // Find the actual packet contents
  bytes = bytes + sizeof(struct udphdr);
  len -= sizeof(struct udphdr);

  // Now proxy the UDP packet to the destination
  struct sockaddr_in dst = { 0 };
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = hdr->daddr;
  dst.sin_port = udp_hdr->uh_dport;

  DROP_GUARD(sendto(found_fd, bytes, len, 0, (struct sockaddr*) &dst, sizeof(dst)) >= 0);
}

void process_tun_packet(event_loop_t* loop, char bytes[MTU], size_t len) {

  // Check we received a full IP packet
  DROP_GUARD(len >= sizeof(struct ip));
  struct ip* hdr = (struct ip*) bytes;

  // TODO: Add IPv6 later once we get this IPv4 thing worked out
  DROP_GUARD(hdr->version == 4);

  char* rest = bytes + sizeof(struct ip);
  len -= sizeof(struct ip);

  switch (hdr->proto) {
    case 1: {
      process_packet_icmp(hdr, rest, len);
      break;
    }
    case 17: {
      process_packet_udp(loop, hdr, rest, len);
    }
    default: {
      printf("Unsupported IP/protocol; dropped\n");
      return;
    }
  }
}

void user_space_ip_proxy(int tunnel_fd) {
  event_loop_t loop;

  loop.epoll_fd = guard(epoll_create(5));

  printf("Epoll FD: %i\n", loop.epoll_fd);

  struct epoll_event events[MAX_EVENTS];

  set_nonblocking(tunnel_fd);
  printf("Made non-blocking\n");

  listen_epollin(loop.epoll_fd, tunnel_fd);
  printf("Registered\n");

  while(true) { 
    ssize_t event_count = epoll_wait(loop.epoll_fd, events, MAX_EVENTS, -1);
    for(size_t i = 0; i < event_count; i++) {
      if (events[i].data.fd == tunnel_fd) {
        char bytes[MTU] = { 0 };
        ssize_t readb = read(tunnel_fd, bytes, MTU);
        if (readb > 0) {
          process_tun_packet(&loop, bytes, readb);
        }
      }
    }
  }
}

int tun_alloc(char const*dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if((fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  return fd;
}

int main() {
  printf("Creating TESTTUN\n");
  int tunfd = tun_alloc("blaketest", IFF_TUN | IFF_NO_PI);
  user_space_ip_proxy(tunfd);
}
