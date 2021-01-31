#include "general.h"
#include "checksum.h"
#include "tun.h"
#include "dev.h"
#include "util.h"
#include "packet.h"

void cleanup_removed_fd(event_loop_t& loop, int fd) {
  stop_listen(loop.epoll_fd, fd);
  fatal_guard(close(fd));

  // Find and remove the outbound path NAT
  auto oit = loop.udp_pairs.begin();
  while (oit != loop.udp_pairs.end()) {
    auto tgt = oit++;
    printf("Scan: %i\n", (*tgt).second.fd);
    if ((*tgt).second.fd == fd) {
      printf("Found and erased from outbound\n");
      loop.udp_pairs.erase(tgt);
    }
  }
}

void remove_fd_from_nat(event_loop_t& loop, int fd) {
  auto it = loop.udp_return.find(fd);
  if (it != loop.udp_return.end()) {
    printf("Removing FD from NAT\n");
    cleanup_removed_fd(loop, fd);
    loop.udp_return.erase(it);
  }
}

void return_a_udp_packet(char* data, size_t len, msg_return& return_addr, event_loop_t& loop, sockaddr_in& addr) {
  printf("Found a return path\n");
  char ipp[1500];
  ssize_t pkt_size;

  printf("%i\n", return_addr.src.sin_addr.s_addr);
  DROP_GUARD((pkt_size = assemble_udp_packet(ipp, 1500, data, len, return_addr.src, addr)) > 0);

  printf("Created a %li byte packet\n", pkt_size);
  write(loop.tunnel_fd, ipp, pkt_size);
}

void return_a_tcp_packet(char* data, size_t len, const msg_return& return_addr, event_loop_t& loop, const sockaddr_in& addr) {
  printf("Found a return path\n");
  char ipp[1500];

  auto tcp_state = return_addr.state;

  bool is_psh = data != nullptr;

  size_t pkt_sz = assemble_tcp_packet(ipp, 1500, tcp_state->us_seq, tcp_state->them_seq + 1, data, len, return_addr.src, addr, is_psh, false, true, false, false);

  if (len > 0) {
    tcp_state->us_seq += len;
  }

  DROP_GUARD(pkt_sz > 0);
  printf("Created a %li byte packet\n", pkt_sz);
  write(loop.tunnel_fd, ipp, pkt_sz);
}

void process_packet_icmp(struct ip* hdr, char* bytes, size_t len) {
  // TODO it is possible to manually do ICMP sockets on Android
  // int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  // Only echo requests will work
  printf("Sorry - I cannot\n");
}

void process_packet_udp(event_loop_t* loop, struct ip* hdr, char* bytes, size_t len) {
  DROP_GUARD(len >= sizeof(struct udphdr));

  struct udphdr* udp_hdr = (struct udphdr *) bytes;
  struct ip_port_protocol id = ip_port_protocol { hdr->daddr, udp_hdr->uh_sport, udp_hdr->uh_dport, IPPROTO_UDP };

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
    loop->udp_pairs[id] = msg_return { new_fd, generate_addr(hdr->saddr, udp_hdr->uh_sport), generate_addr(hdr->daddr, udp_hdr->uh_dport), IPPROTO_UDP, cur_time, nullptr };
    loop->udp_return[new_fd] = loop->udp_pairs[id];
    printf("RETURN: %i\n", loop->udp_return[new_fd].src.sin_addr.s_addr);
    listen_epollin(loop->epoll_fd, new_fd);
    set_nonblocking(new_fd);

    found_fd = new_fd;
  }

  // Find the actual packet contents
  bytes = bytes + sizeof(struct udphdr);
  len -= sizeof(struct udphdr);

  // Now proxy the UDP packet to the destination
  auto dst = lookup_dst_udp(hdr, udp_hdr);

  printf("Trying to send a UDP packet\n");
  DROP_GUARD(sendto(found_fd, bytes, len, 0, (struct sockaddr*) &dst, sizeof(dst)) >= 0);
  printf("Sent UDP packet\n");
}

void process_packet_tcp(event_loop_t& loop, struct ip* hdr, char* bytes, size_t len) {
  printf("New TCP packet\n");

  DROP_GUARD(len >= sizeof(struct tcphdr));
  struct tcphdr* tcp_hdr = (struct tcphdr *) bytes;
  struct ip_port_protocol id = ip_port_protocol { hdr->daddr, tcp_hdr->source, tcp_hdr->dest, IPPROTO_TCP };

  auto fd_scan = loop.udp_pairs.find(id);
  int found_fd;

  if (fd_scan != loop.udp_pairs.end()) {
    printf("Received a FOLLOW UP TCP!\n");
    int fd = fd_scan->second.fd;
    auto ret = fd_scan->second;
    auto tcp_state = fd_scan->second.state;

    if (tcp_hdr->syn && !tcp_hdr->ack) {
      printf("The TCP connection REALLY wants to be friends\n");
    }

    if (!tcp_hdr->syn && tcp_hdr->ack && tcp_state->sent_syn_ack && !tcp_state->recv_first_ack) {
      printf("RECV First ACK. Fully connected!\n");
      printf("Woah. Might actually be OK to proxy data now!?. 黐線\n");
      printf("Preparing epollin\n");
      tcp_state->recv_first_ack = true;
      listen_tcp(loop.epoll_fd, fd_scan->second.fd);
    }

    if (tcp_state->recv_first_ack && tcp_hdr->psh) {
      if (tcp_state->us_ack < ntohl(tcp_hdr->seq)) {
        printf("HEY - HE WANTS TO SEND SOME FUCKING DATA %u %u\nWAKE UP!\n", tcp_state->them_seq, ntohl(tcp_hdr->seq));
        char* data_start = bytes + (tcp_hdr->doff << 2);
        size_t data_size = ntohs(hdr->len) - sizeof(ip) - (tcp_hdr->doff << 2);
        for (size_t i = 0; i < data_size; i++) {
          printf("%c", data_start[i]);
        }
        printf("\n");
        DROP_GUARD(send(fd, data_start, data_size, 0) >= 0);
        tcp_state->us_ack = ntohl(tcp_hdr->seq);

        // Now generate the ack
        printf("ACKIN\n");
        tcp_state->them_seq = ntohl(tcp_hdr->seq) + data_size - 1;
        return_a_tcp_packet(nullptr, 0, ret, loop, ret.dst);
      } else {
        printf("FUCKIN REPEATS %u %u\n", tcp_state->them_seq, ntohl(tcp_hdr->seq));
      }
    }

    if (tcp_hdr->fin) {
      shutdown(fd, SHUT_WR);
      printf("ACKNOWLEDGING THE FIN\n");
      return_a_tcp_packet(nullptr, 0, ret, loop, ret.dst);
    }

    // If we have sent a FIN then the final ACK will close the session
    if (tcp_hdr->ack && tcp_state->closing) {
      printf("Recv ACK on CLOSING\n");

      // Clear up for dead session (This will handle removing the listener)
      remove_fd_from_nat(loop, fd);
    }
  } else {
    // Oooh, this might be a new TCP connection. We need to figure that out (is it a SYN)
    DROP_GUARD(tcp_hdr->syn && !tcp_hdr->ack);

    printf("Creating a new TCP connection\n");

    // Ok, it's a SYN so let's roll with it
    // Create a new TCP FD
    int new_fd;
    DROP_GUARD((new_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) >= 0);
    binddev(new_fd);
    set_nonblocking(new_fd);
    printf("New FD: %i %i\n", new_fd, new_fd >= 0);
    DROP_GUARD(new_fd >= 0);

    auto dst = lookup_dst_tcp(hdr, tcp_hdr);

    DROP_GUARD(connect(new_fd, (sockaddr*) &dst, sizeof(dst)));

    // Fetch the current time
    struct timespec cur_time;
    clock_gettime(CLOCK_MONOTONIC, &cur_time);

    // We next need to add our new TCP connection into the NAT
    // For TCP sessions we create a tcp_state
    struct tcp_state* state = new struct tcp_state;
    state->them_seq = ntohl(tcp_hdr->seq);
    state->them_ack = ntohl(tcp_hdr->ack_seq);
    state->us_seq = rand();
    state->us_ack = state->them_seq;
    state->sent_syn_ack = false;
    state->recv_first_ack = false;
    state->closing = false;

    printf("Initial packet sequences: %u %u\n", state->them_seq, state->them_ack);

    loop.udp_pairs[id] = msg_return { new_fd, generate_addr(hdr->saddr, tcp_hdr->source), generate_addr(hdr->daddr, tcp_hdr->dest), IPPROTO_TCP, cur_time, std::shared_ptr<struct tcp_state>(state) };
    loop.udp_return[new_fd] = loop.udp_pairs[id];

    // Now we don't actually reply to this new connection yet, just add it into the NAT
    // When EPOLLOUT fires on the TCP out or HUP fires then we send a related SYN-ACK or
    // fuck off message 
    initial_listen_tcp(loop.epoll_fd, new_fd);
  }
}

void process_tun_packet(event_loop_t& loop, char bytes[MTU], size_t len) {

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
      process_packet_udp(&loop, hdr, rest, len);
      break;
    }
    case IPPROTO_TCP: {
      process_packet_tcp(loop, hdr, rest, len);
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
      printf("Expiring a NAT entry (FD %i\n)\n", target_fd);
      cleanup_removed_fd(loop, target_fd);
      loop.udp_return.erase(tgt);
    }
  }
}


void user_space_ip_proxy(int tunnel_fd) {
  event_loop_t loop;

  loop.tunnel_fd = tunnel_fd;
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
          process_tun_packet(loop, bytes, readb);
        }
      } else if (events[i].data.fd == loop.timer_fd) {
        printf("TIMER CALL\n");
        clear_timerfd(events[i].data.fd);
        do_nat_cleanup(loop, cur_time);
        printf("TIMER DONE\n");
      } else {
        auto fd_scan = loop.udp_return.find(events[i].data.fd);
        if (fd_scan != loop.udp_return.end()) {
          if (events[i].events & EPOLLIN) {
          printf("FD: %i read\n", events[i].data.fd);
          char buf[65536];
          sockaddr_in addr;
          socklen_t addr_len = sizeof(addr);
          ssize_t len = recvfrom(events[i].data.fd, buf, 1350, 0, (sockaddr *) &addr, &addr_len);

          if (len < 0) {
            continue;
          }

          printf("Read from %i %i a %li byte response\n", addr.sin_addr.s_addr, addr.sin_port, len);
            auto proto = (*fd_scan).second.proto;
            (*fd_scan).second.last_use = cur_time;
            auto ret = (*fd_scan).second;
            printf("Socket Proto: %i\n", proto);
            switch (proto) {
              case IPPROTO_UDP: {
                return_a_udp_packet(buf, len, ret, loop, addr);
                break;
              }
              case IPPROTO_TCP:
                printf("WE GOT A TCP PACKET TO RETURN. FABRICATE A PSH %li\n", len);
                if (len == 0) {
                  printf("Connection gracefully closed\nTime to fab a fucking FIN\n");
                } else {
                  return_a_tcp_packet(buf, len, ret, loop, addr);
                }
                break;
            }
          }
          if (events[i].events & EPOLLOUT) {
            printf("TCP Connected - it's TIME TO SEND A SYN-ACK\n");

            char ipp[1500];
            ssize_t ipp_sz;
            auto ret = (*fd_scan).second;
            auto tcp_state = ret.state;

            sockaddr_in addr = ret.dst;

            printf("SYN-ACK numbers %u %u\n", tcp_state->us_seq, tcp_state->them_seq + 1);
            size_t pkt_sz = assemble_tcp_packet(ipp, 1500, tcp_state->us_seq++, tcp_state->them_seq + 1, NULL, 0, ret.src, addr, false, true, true, false, false);
            DROP_GUARD(pkt_sz > 0);
            DROP_GUARD(write(loop.tunnel_fd, ipp, pkt_sz) >= 0);

            // After sending a SYN-ACK we expect an ACK. Don't touch the REMOTE SOCKET until then
            stop_listen(loop.epoll_fd, events[i].data.fd);

            tcp_state->sent_syn_ack = true;
          }
          if (events[i].events & EPOLLRDHUP) {
            printf("TCP closed - it's time to SEND A FIN\n");

            // Fabricate a FIN
            char ipp[1500];
            ssize_t ipp_sz;
            auto ret = (*fd_scan).second;
            auto tcp_state = ret.state;

            if (!tcp_state->closing) {
              printf("SYN-ACK numbers %u %u\n", tcp_state->us_seq, tcp_state->them_seq + 1);
              size_t pkt_sz = assemble_tcp_packet(ipp, 1500, tcp_state->us_seq, tcp_state->them_seq + 1, NULL, 0, ret.src, ret.dst, false, false, true, true, false);
              DROP_GUARD(pkt_sz > 0);
              DROP_GUARD(write(loop.tunnel_fd, ipp, pkt_sz) >= 0);

              // On the next ACK we actually clean up since we expect an ACK before the session is fully closed
              tcp_state->closing = true;
            } else {
              printf("TCP connection already closing\n");
            }
          }
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
