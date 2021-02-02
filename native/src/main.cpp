#include "general.h"
#include "checksum.h"
#include "tun.h"
#include "dev.h"
#include "util.h"
#include "packet.h"
#include "log.h"
#include "tls.h"

void cleanup_removed_fd(event_loop_t& loop, int fd) {
  stop_listen(loop.epoll_fd, fd);
  fatal_guard(close(fd));

  // Find and remove the outbound path NAT
  auto oit = loop.udp_pairs.begin();
  while (oit != loop.udp_pairs.end()) {
    auto tgt = oit++;
    if ((*tgt).second.fd == fd) {
      debug("GC: Found and erased %i from outbound map", fd);
      loop.udp_pairs.erase(tgt);
    }
  }
}

void remove_fd_from_nat(event_loop_t& loop, int fd) {
  auto it = loop.udp_return.find(fd);
  if (it != loop.udp_return.end()) {
    debug("GC: Removing %i from NAT", fd);
    cleanup_removed_fd(loop, fd);
    loop.udp_return.erase(it);
  }
}

void return_a_udp_packet(char* data, size_t len, msg_return& return_addr, event_loop_t& loop, sockaddr_in& addr) {
  char ipp[MTU];
  ssize_t pkt_sz = assemble_udp_packet(ipp, MTU, data, len, return_addr.src, addr);
  DROP_GUARD(pkt_sz > 0);
  write(loop.tunnel_fd, ipp, pkt_sz);
  loop.udp_bytes_in += len;
}

void return_tcp_rst(const sockaddr_in& src, const sockaddr_in& dst, const event_loop& loop) {
  char ipp[MTU];
  size_t pkt_sz = assemble_tcp_packet(ipp, MTU, 0, 0, nullptr, 0, src, dst, false, false, false, false, true);

  DROP_GUARD(pkt_sz > 0);
  write(loop.tunnel_fd, ipp, pkt_sz);
}

void return_tcp_fin(const msg_return& ret, event_loop_t const& loop) {
  auto tcp_state = ret.state;

  char ipp[MTU];
  size_t pkt_sz = assemble_tcp_packet(ipp, MTU, tcp_state->us_seq++, tcp_state->them_seq + 1, NULL, 0, ret.src, ret.dst, false, false, true, true, false);

  DROP_GUARD(pkt_sz > 0);
  DROP_GUARD(write(loop.tunnel_fd, ipp, pkt_sz) >= 0);
}

void return_a_tcp_packet(char* data, size_t len, const msg_return& return_addr, event_loop_t& loop, const sockaddr_in& addr) {
  auto tcp_state = return_addr.state;

  bool is_psh = len > 0;

  char ipp[MTU];
  size_t pkt_sz = assemble_tcp_packet(ipp, MTU, tcp_state->us_seq, tcp_state->them_seq + 1, data, len, return_addr.src, addr, is_psh, false, true, false, false);

  if (len > 0) {
    tcp_state->us_seq += len;
  }

  DROP_GUARD(pkt_sz > 0);
  write(loop.tunnel_fd, ipp, pkt_sz);
  loop.tcp_bytes_in += len;
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

  //debug("TUN PKT: %i %i %i", hdr->daddr, udp_hdr->uh_sport, udp_hdr->uh_dport);

  auto fd_scan = loop.udp_pairs.find(id);

  int found_fd;

  if (fd_scan != loop.udp_pairs.end()) {
    found_fd = (*fd_scan).second.fd;
  } else {
    // No known UDP socket, open a new one
    debug("UDP: New NAT entry");

    // Create a new UDP FD
    int new_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    binddev(new_fd);
    DROP_GUARD(new_fd >= 0);

    // Fetch the current time
    struct timespec cur_time;
    clock_gettime(CLOCK_MONOTONIC, &cur_time);

    // Register it
    loop.udp_total += 1;
    loop.udp_pairs[id] = msg_return { new_fd, generate_addr(hdr->saddr, udp_hdr->uh_sport), generate_addr(hdr->daddr, udp_hdr->uh_dport), IPPROTO_UDP, cur_time, nullptr };
    loop.udp_return[new_fd] = loop.udp_pairs[id];

    listen_epollin(loop.epoll_fd, new_fd);
    set_nonblocking(new_fd);

    found_fd = new_fd;
  }

  // Find the actual packet contents
  bytes = bytes + sizeof(struct udphdr);
  len -= sizeof(struct udphdr);

  loop.udp_bytes_out += len;

  // Now proxy the UDP packet to the destination
  auto dst = lookup_dst_udp(hdr, udp_hdr);

  //debug("Trying to send a UDP packet");
  DROP_GUARD(sendto(found_fd, bytes, len, 0, (struct sockaddr*) &dst, sizeof(dst)) >= 0);
  //debug("Sent UDP packet");
}

void process_packet_tcp(event_loop_t& loop, struct ip* hdr, char* bytes, size_t len) {

  DROP_GUARD(len >= sizeof(struct tcphdr));
  struct tcphdr* tcp_hdr = (struct tcphdr *) bytes;
  struct ip_port_protocol id = ip_port_protocol { hdr->daddr, tcp_hdr->source, tcp_hdr->dest, IPPROTO_TCP };

  auto fd_scan = loop.udp_pairs.find(id);
  int found_fd;

  if (fd_scan != loop.udp_pairs.end()) {
    int fd = fd_scan->second.fd;
    auto ret = fd_scan->second;
    auto tcp_state = fd_scan->second.state;
    auto ip_len = ntohs(hdr->len);
    auto tcp_seq = ntohl(tcp_hdr->seq);
    auto tcp_last_seq = tcp_state->them_seq;
    auto expected = tcp_state->us_ack;

    debug("TCP %i: Packet Length %u, TCP Seq: %u, Them Seq: %u, Expected Seq: %u", fd, ip_len, tcp_seq, tcp_last_seq, expected);

    if (tcp_hdr->rst) {
      debug("TCP %i: Broken stream (RST).", fd);
      remove_fd_from_nat(loop, fd);
      return;
    }

    if (tcp_hdr->syn) {
      debug("TCP %i: Repeat SYN", fd);
      return;
    }

    if (!tcp_hdr->syn && tcp_hdr->ack && tcp_state->sent_syn_ack && !tcp_state->recv_first_ack) {
      debug("TCP %i: Socket ready for data", fd);
      tcp_state->recv_first_ack = true;
      listen_tcp(loop.epoll_fd, fd);
    }

    // The rest of the process flow requires that we have a completed SYN-SYNACK-ACK connection sequence
    if (!tcp_state->recv_first_ack) {
      return;
    }

    // Calculate how much data there is with the TCP payload
    char* data_start = bytes + (tcp_hdr->doff << 2);
    size_t data_size = ntohs(hdr->len) - sizeof(ip) - (tcp_hdr->doff << 2);

    // If there is data then process and acknowledge it
    if (data_size > 0) {

      // Decide if this packet is a repeat
      bool is_repeat = tcp_last_seq >= tcp_seq;
  
      if (is_repeat) {
        debug("TCP %i: Repeat packet", fd);
        return;
      }

      tcp_state->them_seq += data_size;

      debug("TCP %i: DATA: Sequence: %u (New Expected: %u) Size: %lu", fd, tcp_seq, tcp_state->them_seq, data_size);

      if (tcp_state->first_packet) {

        char* hostname = nullptr;
        int result = parse_tls_header((uint8_t *) data_start, data_size, &hostname);

        if (hostname) {
          debug("SNI: Found %s", hostname);
          bool res = loop.block.block(hostname);
          if (res) {
            debug("SNI: Dropping connection\n");
            loop.blocked += 1;
            return_tcp_fin(ret, loop);
            remove_fd_from_nat(loop, fd);
            return;
          }
        }

        free(hostname);
        tcp_state->first_packet = false;
      }

      // Update statistics
      loop.tcp_bytes_out += data_size;

      // Send this on to the target
      DROP_GUARD(send(fd, data_start, data_size, MSG_NOSIGNAL) >= 0);

      // Acknowledge the receipt by transmitting back a packet with 0 data but the ACK field set
      return_a_tcp_packet(nullptr, 0, ret, loop, ret.dst);
    }

    if (tcp_hdr->fin) {
      tcp_state->them_seq += 1;
      shutdown(fd, SHUT_WR);
      debug("TCP %i: Client has shutdown write half of stream", fd);
      tcp_state->close_wr = true;

      // SYN and FIN increment the sequence number by one 
      return_a_tcp_packet(nullptr, 0, ret, loop, ret.dst);
    }

    // If we have sent a FIN then the final ACK will close the session
    if (tcp_hdr->ack && tcp_state->close_rd) {
      debug("TCP %i: Stream has acknowledged FIN", fd);
    } 

    // Both sides are closed
    if (tcp_state->close_wr && tcp_state->ack_rd && tcp_state->close_rd) {
      debug("TCP %i: Both sides of the connection have closed and acknowledged", fd);
      // Clear up for dead session (This will handle removing the listener)
      remove_fd_from_nat(loop, fd);
    }
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
    binddev(new_fd);
    set_nonblocking(new_fd);
    set_fast_tcp(new_fd);
    debug("New FD: %i %i", new_fd, new_fd >= 0);
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
    state->close_wr = false;
    state->close_rd = false;
    state->ack_rd = false;
    state->first_packet = true;

    debug("TCP: New Stream. Initial packet sequences: %u %u", state->them_seq, state->them_ack);
    loop.tcp_total += 1;

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

  const uint32_t my_addr = inet_addr("10.0.0.2");
  DROP_GUARD(hdr->saddr == my_addr);

  // TODO: Add IPv6 later once we get this IPv4 thing worked out
  //debug("IP HDR Version: %i %i", hdr->version, hdr->ihl);
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
  auto it = loop.udp_return.begin();
  while (it != loop.udp_return.end()) {
    auto tgt = it++;
    auto proto = tgt->second.proto;

    if (proto == IPPROTO_TCP) {
      tcp += 1;
    } else if (proto == IPPROTO_UDP) {
      udp += 1;

      uint64_t age = cur_time.tv_sec - (*tgt).second.last_use.tv_sec;

      // UDP sessions don't die, we just evict the NAT mapping after 30s
      if (age > 30) {
        int target_fd = tgt->second.fd;
        cleanup_removed_fd(loop, target_fd);
        loop.udp_return.erase(tgt);
        expired += 1;
      }
    }
  }

  debug("STATE: UDP: %lu / %lu (%lu / %lu) bytes TCP: %lu / %lu (%lu / %lu) EXPIRED: %lu BLOCKED (THIS SESSION): %lu", udp, loop.udp_total, loop.udp_bytes_in, loop.udp_bytes_out, tcp, loop.tcp_total, loop.tcp_bytes_in, loop.tcp_bytes_out, expired, loop.blocked);
}


void user_space_ip_proxy(int tunnel_fd, BlockList const& list) {
  event_loop_t loop(list);

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
  listen_epollin(loop.epoll_fd, tunnel_fd);
  listen_epollin(loop.epoll_fd, loop.timer_fd);
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
      } else if (events[i].data.fd == loop.timer_fd) {
        clear_timerfd(events[i].data.fd);
        do_nat_cleanup(loop, cur_time);
      } else {
        auto fd_scan = loop.udp_return.find(events[i].data.fd);
        if (fd_scan != loop.udp_return.end()) {
          if (events[i].events & EPOLLIN) {
          char buf[65536];
          sockaddr_in addr;
          socklen_t addr_len = sizeof(addr);
          ssize_t len = recvfrom(events[i].data.fd, buf, 1350, 0, (sockaddr *) &addr, &addr_len);

          if (len < 0) {
            debug("zero read error");
            continue;
          }

          debug("Read from %i %i a %li byte response", addr.sin_addr.s_addr, addr.sin_port, len);
            auto proto = (*fd_scan).second.proto;
            (*fd_scan).second.last_use = cur_time;
            auto ret = (*fd_scan).second;
            //debug("Socket Proto: %i", proto);
            switch (proto) {
              case IPPROTO_UDP: {
                return_a_udp_packet(buf, len, ret, loop, addr);
                break;
              }
              case IPPROTO_TCP:
                //debug("WE GOT A TCP PACKET TO RETURN. FABRICATE A PSH %li", len);
                if (len == 0) {
                  debug("Connection gracefully closed\nTime to fab a fucking FIN");
                } else {
                  return_a_tcp_packet(buf, len, ret, loop, addr);
                }
                break;
            }
          } else if (events[i].events & EPOLLOUT) {
            debug("TCP Connected - it's TIME TO SEND A SYN-ACK");

            char ipp[1500];
            ssize_t ipp_sz;
            auto ret = (*fd_scan).second;
            auto tcp_state = ret.state;

            sockaddr_in addr = ret.dst;

            debug("SYN-ACK numbers %u %u", tcp_state->us_seq, tcp_state->them_seq + 1);
            size_t pkt_sz = assemble_tcp_packet(ipp, 1500, tcp_state->us_seq++, tcp_state->them_seq + 1, NULL, 0, ret.src, addr, false, true, true, false, false);
            DROP_GUARD(pkt_sz > 0);
            DROP_GUARD(write(loop.tunnel_fd, ipp, pkt_sz) >= 0);

            // After sending a SYN-ACK we expect an ACK. Don't touch the REMOTE SOCKET until then
            stop_listen(loop.epoll_fd, events[i].data.fd);

            tcp_state->sent_syn_ack = true;
          }
          if (events[i].events & (EPOLLHUP | EPOLLRDHUP)) {
            debug("TCP closed - it's time to SEND A FIN");

            // Fabricate a FIN
            char ipp[1500];
            ssize_t ipp_sz;
            auto ret = (*fd_scan).second;
            auto tcp_state = ret.state;

            debug("TCP %i: Upstream closed. Generating FIN with SYN-ACK numbers %u %u", events[i].data.fd, tcp_state->us_seq, tcp_state->them_seq + 1);
            return_tcp_fin(ret, loop);

            // On the next ACK we actually clean up since we expect an ACK before the session is fully closed
            tcp_state->close_rd = true;
            stop_listen(loop.epoll_fd, events[i].data.fd); 
          }
        }
      }
    }
    clock_gettime(CLOCK_MONOTONIC, &fin_time);
    debug("FRAME: Took %lus", fin_time.tv_sec - cur_time.tv_sec);
  }
}

#include "block_list.h"

int main() {
  FILE* blist = fopen("lists/base.txt", "r");
  BlockList b(blist);
  debug("Creating TESTTUN");
  int tunfd = tun_alloc("blaketest", IFF_TUN | IFF_NO_PI);
  user_space_ip_proxy(tunfd, b);
}
