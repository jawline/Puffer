#include "general.h"
#include "checksum.h"
#include "tun.h"
#include "dev.h"
#include "util.h"
#include "packet.h"
#include "log.h"
#include "tls.h"
#include <sys/timerfd.h>
#include <arpa/inet.h>
#include "udp.h"
#include "tcp.h"

void cleanup_removed_fd(event_loop_t& loop, int fd) {
  stop_listen(loop.epoll_fd, fd);
  fatal_guard(close(fd));

  // Find and remove the outbound path NAT
  auto oit = loop.outbound_nat.begin();
  while (oit != loop.outbound_nat.end()) {
    auto tgt = oit++;
    if (tgt->second->fd == fd) {
      //debug("GC: Found and erased %i from outbound map", fd);
      loop.outbound_nat.erase(tgt);
    }
  }
}

void remove_fd_from_nat(event_loop_t& loop, int fd) {
  auto it = loop.inbound_nat.find(fd);
  if (it != loop.inbound_nat.end()) {
    debug("GC: Removing %i from NAT", fd);
    cleanup_removed_fd(loop, fd);
    loop.inbound_nat.erase(it);
  }
}

void process_packet_icmp(struct ip* hdr, char* bytes, size_t len) {
  // TODO it is possible to manually do ICMP sockets on Android
  // int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  // Only echo requests will work
  //debug("Sorry - I cannot");
}

void process_packet_udp(event_loop_t& loop, struct ip* hdr, char* bytes, size_t len) {
  DROP_GUARD(len >= sizeof(struct udphdr));

  struct udphdr* udp_hdr = (struct udphdr *) bytes;
  struct ip_port_protocol id = ip_port_protocol { hdr->daddr, udp_hdr->uh_sport, udp_hdr->uh_dport, IPPROTO_UDP };

  auto fd_scan = loop.outbound_nat.find(id);
  std::shared_ptr<Socket> udp_socket;

  if (fd_scan != loop.outbound_nat.end()) {
    udp_socket = fd_scan->second; 
  } else {
    // No known UDP socket, open a new one
    debug("UDP: New NAT entry");

    // Create a new UDP FD
    int new_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    binddev(loop, new_fd);
    set_nonblocking(new_fd);
    DROP_GUARD(new_fd >= 0);

    udp_socket = std::shared_ptr<Socket>(new UdpStream(new_fd, generate_addr(hdr->saddr, udp_hdr->uh_sport), generate_addr(hdr->daddr, udp_hdr->uh_dport), IPPROTO_UDP));

    loop.register_udp(id, udp_socket);
  }

  // Find the actual packet contents
  bytes = bytes + sizeof(struct udphdr);
  len -= sizeof(struct udphdr);

  udp_socket->on_tun(loop.tunnel_fd, (char*) hdr, (char*) udp_hdr, bytes, len);
}

void process_packet_tcp(event_loop_t& loop, struct ip* hdr, char* bytes, size_t len) {
  DROP_GUARD(len >= sizeof(struct tcphdr));
  struct tcphdr* tcp_hdr = (struct tcphdr *) bytes;
  struct ip_port_protocol id = ip_port_protocol { hdr->daddr, tcp_hdr->source, tcp_hdr->dest, IPPROTO_TCP };

  debug("Source: %s %i", inet_ntoa(in_addr { hdr->saddr }), tcp_hdr->source);
  debug("Dest: %s %i", inet_ntoa(in_addr { hdr->daddr }), tcp_hdr->dest);

  auto fd_scan = loop.outbound_nat.find(id);
  int found_fd;

  if (fd_scan != loop.outbound_nat.end()) {

  } else {
    // Oooh, this might be a new TCP connection. We need to figure that out (is it a SYN)

    // If this is not the SYN first packet then something is wrong. send an RST and drop
    if (!(tcp_hdr->syn && !tcp_hdr->ack)) {
      //return_tcp_rst(generate_addr(hdr->saddr, tcp_hdr->source), generate_addr(hdr->daddr, tcp_hdr->dest), loop);
      return;
    }

    debug("Creating a new TCP connection");

    // Ok, it's a SYN so let's roll with it
    // Create a new TCP FD
    int new_fd;
    DROP_GUARD((new_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) >= 0);
    binddev(loop, new_fd);
    set_nonblocking(new_fd);
    set_fast_tcp(new_fd);
    debug("New FD: %i %i", new_fd, new_fd >= 0);
    DROP_GUARD(new_fd >= 0);

    auto dst = lookup_dst_tcp(hdr, tcp_hdr);

    DROP_GUARD(connect(new_fd, (sockaddr*) &dst, sizeof(dst)));

    auto tcp_socket = std::shared_ptr<Socket>(new TcpStream(new_fd, generate_addr(hdr->saddr, tcp_hdr->source), generate_addr(hdr->daddr, tcp_hdr->dest), IPPROTO_TCP, ntohl(tcp_hdr->seq)));

    loop.register_tcp(id, tcp_socket);
  }
}

void process_tun_packet(event_loop_t& loop, char bytes[MTU], size_t len) {

  // Check we received a full IP packet
  DROP_GUARD(len >= sizeof(struct ip));
  struct ip* hdr = (struct ip*) bytes;

  //const uint32_t my_addr = inet_addr("10.0.0.2");
  //hdr->saddr = my_addr;
  //DROP_GUARD(hdr->saddr == my_addr);

  // TODO: Add IPv6 later once we get this IPv4 thing worked out
  debug("IP HDR Version: %i %i", hdr->version, hdr->ihl);
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
    case IPPROTO_TCP: {
      process_packet_tcp(loop, hdr, rest, len);
      break;
    }
    default: {
      debug("Unsupported IP/protocol; dropped %i", hdr->proto);
      return;
    }
  }
}

void do_nat_cleanup(event_loop_t& loop, timespec& cur_time) {
  size_t udp = 0;
  size_t tcp = 0;
  size_t expired = 0;

  // Now expire any session that has been around too long
  auto it = loop.inbound_nat.begin();
  while (it != loop.inbound_nat.end()) {
    auto tgt = it++;
    auto proto = tgt->second->proto;

    if (proto == IPPROTO_TCP) {
      tcp += 1;
    } else if (proto == IPPROTO_UDP) {
      udp += 1;

      uint64_t age = cur_time.tv_sec - (*tgt).second->last_use.tv_sec;

      // UDP sessions don't die, we just evict the NAT mapping after 30s
      if (age > 30) {
        int target_fd = tgt->second->fd;
        cleanup_removed_fd(loop, target_fd);
        loop.inbound_nat.erase(tgt);
        expired += 1;
      }
    }
  }

  report(loop, udp, tcp, expired);
}

void user_space_ip_proxy(int tunnel_fd, event_loop_t loop) {

  loop.tunnel_fd = tunnel_fd;
  loop.epoll_fd = epoll_create(5);
  loop.timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);

  fatal_guard(loop.epoll_fd);
  fatal_guard(loop.timer_fd);

  struct itimerspec timespec = { 0 };
  timespec.it_value.tv_sec = 5;
  timespec.it_interval.tv_sec = 5;

  timerfd_settime(loop.timer_fd, 0, &timespec, NULL);

  debug("Epoll FD: %i", loop.epoll_fd);

  struct epoll_event events[MAX_EVENTS];

  set_nonblocking(tunnel_fd);

  debug("Preparing epoll listeners");
  loop.listen_in(tunnel_fd);
  loop.listen_in(loop.quit_fd);
  loop.listen_in(loop.timer_fd);
  debug("Setup epoll listeners");

  struct timespec cur_time;
  struct timespec fin_time;

  while(true) { 
    ssize_t event_count = epoll_wait(loop.epoll_fd, events, MAX_EVENTS, -1);
    clock_gettime(CLOCK_MONOTONIC, &cur_time);
    for(size_t i = 0; i < event_count; i++) {
      if (events[i].data.fd == tunnel_fd) {
        char bytes[MTU] = { 0 };
        ssize_t readb;
        while ((readb = read(tunnel_fd, bytes, MTU)) > 0) {
          process_tun_packet(loop, bytes, readb);
        }
      } else if (events[i].data.fd == loop.quit_fd) {
        debug("TODO: Appropriately tear it all down. Kill everything. Cleanup.");
        return;
      } else if (events[i].data.fd == loop.timer_fd) {
        clear_timerfd(events[i].data.fd);
        do_nat_cleanup(loop, cur_time);
      } else {
        auto fd_scan = loop.inbound_nat.find(events[i].data.fd);
        if (fd_scan != loop.inbound_nat.end()) {
          if (events[i].events & EPOLLIN) {
            char buf[65536];
            sockaddr_in addr;
            socklen_t addr_len = sizeof(addr);
            ssize_t len = recvfrom(events[i].data.fd, buf, 1350, 0, (sockaddr *) &addr, &addr_len);

            if (len < 0) {
              debug("zero read error");
              continue;
            }

            debug("READ: %i SZ: %lu", events[i].data.fd, len);
            auto proto = fd_scan->second->proto;
            fd_scan->second->last_use = cur_time;
            fd_scan->second->on_data(loop.tunnel_fd, buf, len, loop.stat);
          }
          fd_scan->second->on_sock(loop.tunnel_fd, events[i].events, loop.stat);
        }
      }
    }
    clock_gettime(CLOCK_MONOTONIC, &fin_time);
  }
}

int main() {
  int fds[2];
  fatal_guard(pipe(fds));

  FILE* blist = fopen("lists/base.txt", "r");
  BlockList b(blist);
  event_loop_t loop(b);
  loop.quit_fd = fds[0];
  debug("Creating TESTTUN");
  int tunfd = tun_alloc("blaketest", IFF_TUN | IFF_NO_PI);
  user_space_ip_proxy(tunfd, loop);
}
