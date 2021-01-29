#include "general.h"
#include "checksum.h"
#include "tun.h"
#include "dev.h"
#include "util.h"
#include "packet.h"

void process_packet_icmp(struct ip* hdr, char* bytes, size_t len) {
  // TODO it is possible to manually do ICMP sockets on Android
  // int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  // Only echo requests will work
  printf("Sorry - I cannot\n");
}

void process_packet_udp(event_loop_t* loop, struct ip* hdr, char* bytes, size_t len) {
  DROP_GUARD(len >= sizeof(struct udphdr));

  struct udphdr* udp_hdr = (struct udphdr *) bytes;
  struct ip_port id = ip_port { hdr->daddr, udp_hdr->uh_sport, udp_hdr->uh_dport };

  printf("TUN PKT: %i %i %i\n", hdr->daddr, udp_hdr->uh_sport, udp_hdr->uh_dport);

  auto fd_scan = loop->udp_pairs.find(id);

  int found_fd;

  if (fd_scan != loop->udp_pairs.end()) {
    found_fd = (*fd_scan).second.fd;
  } else {
    // No known UDP socket, open a new one

    // Create a new UDP FD
    int new_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    binddev(new_fd);
    printf("New FD: %i %i\n", new_fd, new_fd >= 0);
    DROP_GUARD(new_fd >= 0);

    // Fetch the current time
    struct timespec cur_time;
    clock_gettime(CLOCK_MONOTONIC, &cur_time);

    // Register it
    loop->udp_pairs[id] = msg_return { new_fd, hdr->saddr, udp_hdr->uh_sport, IPPROTO_UDP, cur_time, nullptr };
    loop->udp_return[new_fd] = loop->udp_pairs[id];
    printf("RETURN: %i\n", loop->udp_return[new_fd].src_ip);
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

  printf("Trying to send a UDP packet\n");
  DROP_GUARD(sendto(found_fd, bytes, len, 0, (struct sockaddr*) &dst, sizeof(dst)) >= 0);
  printf("Sent UDP packet\n");
}

void process_packet_tcp(event_loop_t* loop, struct ip* hdr, char* bytes, size_t len) {
  DROP_GUARD(len >= sizeof(struct tcphdr));
  struct tcphdr* tcp_hdr = (struct tcphdr *) bytes;
  struct ip_port id = ip_port { hdr->daddr, tcp_hdr->source, tcp_hdr->dest };

  auto fd_scan = loop->udp_pairs.find(id);
  int found_fd;

  if (fd_scan != loop->udp_pairs.end()) {
    
  } else {
    // Oooh, this might be a new TCP connection. We need to figure that out (is it a SYN)
    DROP_GUARD(tcp_hdr->syn);
  }
}

void process_tun_packet(event_loop_t* loop, char bytes[MTU], size_t len) {

  // Check we received a full IP packet
  DROP_GUARD(len >= sizeof(struct ip));
  struct ip* hdr = (struct ip*) bytes;

  // TODO: Add IPv6 later once we get this IPv4 thing worked out
  printf("IP HDR Version: %i %i\n", hdr->version, hdr->ihl);
  DROP_GUARD(hdr->version == 4);

  char* rest = bytes + sizeof(struct ip);
  len -= sizeof(struct ip);

  switch (hdr->proto) {
    case IPPROTO_ICMP: {
      process_packet_icmp(hdr, rest, len);
      break;
    }
    case IPPROTO_UDP: {
      process_packet_udp(loop, hdr, rest, len);
      break;
    }
    default: {
      printf("Unsupported IP/protocol; dropped %i\n", hdr->proto);
      return;
    }
  }
}

void do_nat_cleanup(event_loop_t& loop, timespec& cur_time) {
  // Now expire any session that has been around too long
  auto it = loop.udp_return.begin();
  while (it != loop.udp_return.end()) {
    auto tgt = it++;
    uint64_t age = cur_time.tv_sec - (*tgt).second.last_use.tv_sec;
    printf("%ld\n", age);
    if (age > 30) {
      int target_fd = (*tgt).second.fd;
      printf("Expiring a UDP session (FD %i\n)\n", target_fd);
      fatal_guard(close(target_fd));

      // Find and remove the outbound path NAT
      auto oit = loop.udp_pairs.begin();
      while (oit != loop.udp_pairs.end()) {
        auto tgt = oit++;
        printf("Scan: %i\n", (*tgt).second.fd);
        if ((*tgt).second.fd == target_fd) {
          printf("Found and erased from outbound\n");
          loop.udp_pairs.erase(tgt);
        }
      }
      loop.udp_return.erase(tgt);
    }
  }
}

void user_space_ip_proxy(int tunnel_fd) {
  event_loop_t loop;

  loop.epoll_fd = fatal_guard(epoll_create(5));
  loop.timer_fd = fatal_guard(timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK));

  struct itimerspec timespec = { 0 };
  timespec.it_value.tv_sec = 5;
  timespec.it_interval.tv_sec = 5;

  timerfd_settime(loop.timer_fd, 0, &timespec, NULL);

  printf("Epoll FD: %i\n", loop.epoll_fd);

  struct epoll_event events[MAX_EVENTS];

  set_nonblocking(tunnel_fd);
  printf("Made non-blocking\n");

  printf("Preparing epoll listeners\n");
  listen_epollin(loop.epoll_fd, tunnel_fd);
  listen_epollin(loop.epoll_fd, loop.timer_fd);
  printf("Setup epoll listeners\n");

  struct timespec cur_time;

  while(true) { 
    ssize_t event_count = epoll_wait(loop.epoll_fd, events, MAX_EVENTS, -1);
    clock_gettime(CLOCK_MONOTONIC, &cur_time);
    for(size_t i = 0; i < event_count; i++) {
      if (events[i].data.fd == tunnel_fd) {
        char bytes[MTU] = { 0 };
        ssize_t readb = read(tunnel_fd, bytes, MTU);
        if (readb > 0) {
          process_tun_packet(&loop, bytes, readb);
        }
      } else if (events[i].data.fd == loop.timer_fd) {
        printf("TIMER CALL\n");
        clear_timerfd(events[i].data.fd);
        do_nat_cleanup(loop, cur_time);
        printf("TIMER DONE\n");
      } else {
        printf("FD: %i read\n", events[i].data.fd);
        char buf[65536];
        sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        ssize_t len = recvfrom(events[i].data.fd, buf, 65536, 0, (sockaddr *) &addr, &addr_len);
        printf("Read from %i %i a %li byte response\n", addr.sin_addr.s_addr, addr.sin_port, len);
        auto fd_scan = loop.udp_return.find(events[i].data.fd);
        if (fd_scan != loop.udp_return.end()) {
          printf("Found a return path\n");
          char ipp[1500];
          ssize_t pkt_size;
          msg_return return_addr = (*fd_scan).second;
          printf("%i\n", return_addr.src_ip);
          DROP_GUARD((pkt_size = assemble_udp_packet(ipp, 1500, buf, len, &return_addr, &addr)) > 0);
          printf("Created a %li byte packet\n", pkt_size);
          (*fd_scan).second.last_use = cur_time;
          write(tunnel_fd, ipp, pkt_size);
        }
      }
    }
  }
}

int main() {
  printf("Creating TESTTUN\n");
  int tunfd = tun_alloc("blaketest", IFF_TUN | IFF_NO_PI);
  user_space_ip_proxy(tunfd);
}
