#ifndef _GR
#define _GR
#include "network.h"
#include "socket.h"
#include "general.h"
#include "util.h"
#include "udp.h"
#include "tcp.h"

class EventLoop {
private:

  stats stat;

  int tunnel_fd;
  int epoll_fd;
  int quit_fd;
  int timer_fd;

  std::map<ip_port_protocol, std::shared_ptr<Socket>> outbound_nat;
  std::map<int, std::shared_ptr<Socket>> inbound_nat;

  BlockList block;

#if defined(__ANDROID__)
  JNIEnv *jni_env;
  jobject jni_service;
  jclass jni_service_class;
  jmethodID protect;
  jmethodID report;
#endif

  inline void register_udp(ip_port_protocol const& id, std::shared_ptr<Socket> new_entry) {
    debug("OUTBOUND NAT %i %i", id.src_port, id.dst_port);
    stat.udp_total += 1;
    outbound_nat[id] = new_entry;
    inbound_nat[new_entry->fd] = new_entry;
    listen_in(new_entry->fd);
  }

  inline void register_tcp(ip_port_protocol const& id, std::shared_ptr<Socket> new_entry) {
    stat.tcp_total += 1;
    outbound_nat[id] = new_entry;
    inbound_nat[new_entry->fd] = new_entry;

    // Now we don't actually reply to this new connection yet, just add it into the NAT
    // When EPOLLOUT fires on the TCP out or HUP fires then we send a related SYN-ACK or
    // fuck off message 
    listen_initial_tcp(new_entry->fd);
  }

  inline void listen_initial_tcp(int fd) {
    struct epoll_event event = { 0 };
    event.events = EPOLLOUT | EPOLLHUP;
    event.data.fd = fd;
    fatal_guard(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event));
  }

  inline void listen_in(int fd) {
    struct epoll_event event = { 0 };
    event.events = EPOLLIN;
    event.data.fd = fd;
    fatal_guard(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event));
  }


  inline void cleanup_removed_fd(int fd) {
    stop_listen(epoll_fd, fd);

    // Find and remove the outbound path NAT
    auto oit = outbound_nat.begin();
    while (oit != outbound_nat.end()) {
      auto tgt = oit++;
      if (tgt->second->fd == fd) {
        debug("GC: Found and erased %i from outbound map", fd);
        outbound_nat.erase(tgt);
      }
    }
  }

  inline void remove_fd_from_nat(int fd) {
    auto it = inbound_nat.find(fd);
    if (it != inbound_nat.end()) {
      debug("GC: Removing %i from NAT", fd);
      cleanup_removed_fd(fd);
      inbound_nat.erase(it);
    }
  }

  inline void report(size_t udp, size_t tcp, size_t expired) {
      debug("STATE: UDP: %zu / %zu (%zu / %zu) bytes TCP: %zu / %zu (%zu / %zu) EXPIRED: %zu BLOCKED (THIS SESSION): %zu", udp, stat.udp_total, stat.udp_bytes_in, stat.udp_bytes_out, tcp, stat.tcp_total, stat.tcp_bytes_in, stat.tcp_bytes_out, expired, stat.blocked);
  #if defined(__ANDROID__)
      jni_env->CallVoidMethod(jni_service, report, (jlong) tcp, (jlong) stat.tcp_total, (jlong) udp, (jlong) stat.udp_total, (jlong) (stat.tcp_bytes_in + stat.udp_bytes_in), (jlong) (stat.tcp_bytes_out + stat.udp_bytes_out), (jlong) stat.blocked);
  #else
  #endif
  }


  /// This function protects us from the VPN device
  /// TODO: Figure out how to drive this from android (I think VpnBuilder can take care of it)
  inline void binddev(int fd) {
  #if defined(__ANDROID__)
      jni_env->CallVoidMethod(jni_service, protect, fd);
  #else
    debug("Registered this device!");
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "wlp2s0");
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
      printf("Woof\n");
    }
  #endif
  }

  inline void do_nat_cleanup(timespec const& cur_time) {
    size_t udp = 0;
    size_t tcp = 0;
    size_t expired = 0;

    // Now expire any session that has been around too long
    auto it = inbound_nat.begin();
    while (it != inbound_nat.end()) {

      // Iterate the iterator first but keep a handle on the old one.
      // this allows us to erase and continue looping
      auto tgt = it++;
      auto socket = tgt->second;

      switch (socket->proto) {
        case IPPROTO_TCP:
          tcp += 1;
          break;
        case IPPROTO_UDP:
          udp += 1;
          uint64_t age = cur_time.tv_sec - socket->last_use.tv_sec;
          // UDP sessions don't die, we just evict the NAT mapping after 30s of inactivity
          if (age > UDP_NAT_TIMEOUT_SECONDS) {
            cleanup_removed_fd(socket->fd);
            inbound_nat.erase(tgt);
            expired += 1;
          }
          break;
      }
    }

    report(udp, tcp, expired);
  }

  inline void process_packet_udp(struct ip* hdr, char* bytes, size_t len) {
    DROP_GUARD(len >= sizeof(struct udphdr));
    struct udphdr* udp_hdr = (struct udphdr *) bytes;
    struct ip_port_protocol id = ip_port_protocol { hdr->daddr, udp_hdr->uh_sport, udp_hdr->uh_dport, IPPROTO_UDP };

    auto fd_scan = outbound_nat.find(id);
    std::shared_ptr<Socket> udp_socket;

    if (fd_scan != outbound_nat.end()) {
      udp_socket = fd_scan->second;
    } else {
      // No known UDP socket, open a new one
      debug("UDP: New NAT entry");

      // Create a new UDP FD
      int new_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      binddev(new_fd);
      set_nonblocking(new_fd);
      DROP_GUARD(new_fd >= 0);

      udp_socket = std::shared_ptr<Socket>(new UdpStream(new_fd, generate_addr(hdr->saddr, udp_hdr->uh_sport), generate_addr(hdr->daddr, udp_hdr->uh_dport), IPPROTO_UDP));

      register_udp(id, udp_socket);
    }

    // Find the actual packet contents
    bytes = bytes + sizeof(struct udphdr);
    len -= sizeof(struct udphdr);

    if (udp_socket->on_tun(tunnel_fd, epoll_fd, (char*) hdr, (char*) udp_hdr, bytes, len, block, stat)) {
      remove_fd_from_nat(fd_scan->second->fd);
    }
  }

  inline void process_packet_tcp(struct ip* hdr, char* bytes, size_t len) {
    debug("TCP: Lookup %zu", len);

    DROP_GUARD(len >= sizeof(struct tcphdr));
    struct tcphdr* tcp_hdr = (struct tcphdr *) bytes;
    struct ip_port_protocol id = ip_port_protocol { hdr->daddr, tcp_hdr->source, tcp_hdr->dest, IPPROTO_TCP };

    debug("Source: %s %i", inet_ntoa(in_addr { hdr->saddr }), tcp_hdr->source);
    debug("Dest: %s %i", inet_ntoa(in_addr { hdr->daddr }), tcp_hdr->dest);

    auto fd_scan = outbound_nat.find(id);
    int found_fd;

    for (auto it : outbound_nat) {
        debug("NAT entry list: %s %i %i %i", inet_ntoa(in_addr { it.first.ip }), it.first.src_port, it.first.dst_port, it.first.proto);
    }

    if (fd_scan != outbound_nat.end()) {

      // TODO: Guards!
      char* data_start = bytes + (tcp_hdr->doff << 2);
      size_t data_size = ntohs(hdr->len) - sizeof(ip) - (tcp_hdr->doff << 2);

      log("TCP: Message %zu bytes", data_size);

      if (fd_scan->second->on_tun(tunnel_fd, epoll_fd, (char*) hdr, (char*) tcp_hdr, data_start, data_size, block, stat)) {
        log("TCP: on_tun requested %i be removed from NAT", fd_scan->second->fd);
        remove_fd_from_nat(fd_scan->second->fd);
      }
    } else {
      // Oooh, this might be a new TCP connection. We need to figure that out (is it a SYN)
      // If this is not the SYN first packet then something is wrong. send an RST and drop
      if (!(tcp_hdr->syn && !tcp_hdr->ack)) {
        debug("TCP: Not initial SYN %i %i %i", tcp_hdr->syn, tcp_hdr->ack, tcp_hdr->fin);
        TcpStream::return_tcp_rst(tunnel_fd, generate_addr(hdr->saddr, tcp_hdr->source), generate_addr(hdr->daddr, tcp_hdr->dest));
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

      auto tcp_socket = std::shared_ptr<Socket>(new TcpStream(new_fd, generate_addr(hdr->saddr, tcp_hdr->source), generate_addr(hdr->daddr, tcp_hdr->dest), IPPROTO_TCP, ntohl(tcp_hdr->seq)));
      register_tcp(id, tcp_socket);
    }
  }

  inline void process_packet_icmp(struct ip* hdr, char* bytes, size_t len) {
    // TODO it is possible to manually do ICMP sockets on Android
    // int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    // Only echo requests will work
    debug("ICMP currently unsupported - TODO");
  }

  inline void process_tun_packet(char bytes[MTU], size_t len) {

    // Check we received a full IP packet
    DROP_GUARD(len >= sizeof(struct ip));
    struct ip* hdr = (struct ip*) bytes;

    // TODO: Add IPv6 later once we get this IPv4 thing worked out
    debug("IP HDR Version: %i %i %i", hdr->version, hdr->ihl, hdr->proto);
    DROP_GUARD(hdr->version == 4);

    size_t ip_header_size_bytes = hdr->ihl << 2;

    DROP_GUARD(ip_header_size_bytes >= IP_HEADER_MIN_SIZE);

    char* rest = bytes + ip_header_size_bytes;
    len -= ip_header_size_bytes;

    switch (hdr->proto) {
      case IPPROTO_ICMP: {
        process_packet_icmp(hdr, rest, len);
        break;
      }
      case IPPROTO_UDP: {
        process_packet_udp(hdr, rest, len);
        break;
      }
      case IPPROTO_TCP: {
        process_packet_tcp(hdr, rest, len);
        break;
      }
      default: {
        debug("Unsupported IP/protocol; dropped %i", hdr->proto);
        return;
      }
    }
  }

  inline void setup_timer() {
    struct itimerspec timespec = { 0 };
    timespec.it_value.tv_sec = 5;
    timespec.it_interval.tv_sec = 5;
    fatal_guard(timerfd_settime(timer_fd, 0, &timespec, NULL));
  }

  inline void on_tun_in() {
    char bytes[MTU] = { 0 };
    ssize_t readb;
    while ((readb = read(tunnel_fd, bytes, MTU)) > 0) {
      process_tun_packet(bytes, readb);
    }
  }

  inline void on_timer_in(timespec const& cur_time) {
    clear_timerfd(timer_fd);
    do_nat_cleanup(cur_time);
  }

  inline void socket_on_network_event(int events, timespec const& cur_time, std::shared_ptr<Socket> const& socket) {
    bool should_remove = false;

    if (events & EPOLLIN) {
      debug("SOCK: %i awaiting data", socket->fd);

      char buf[MTU];
      sockaddr_in addr;
      socklen_t addr_len = sizeof(addr);

      while (true) {
        ssize_t len = recvfrom(socket->fd, buf, 1350, 0, (sockaddr *) &addr, &addr_len);

        debug("SOCK: %i read sz: %li", socket->fd, len);

        if (len <= 0) {
          break;
        }

        if (socket->on_data(tunnel_fd, epoll_fd, buf, len, stat)) {
          log("SOCK: %i on-data requests NAT kill", socket->fd);
          should_remove = true;
          break;
        }
      }

      // Update the last-use time
      socket->last_use = cur_time;
    }

    if (socket->on_sock(tunnel_fd, epoll_fd, events, stat)) {
      log("SOCK: %i on-sock requests NAT kill", socket->fd);
      should_remove = true;
    }

    if (should_remove) {
      log("SOCK: %i removed from NAT", socket->fd);
      remove_fd_from_nat(socket->fd);
    }
  }

  inline void on_network_event(epoll_event const& event, timespec const& cur_time) {
    debug("Network socket event");
    auto event_fd = event.data.fd;
    auto events = event.events;
    auto fd_scan = inbound_nat.find(event_fd);
    if (fd_scan != inbound_nat.end()) {
      auto socket = fd_scan->second;
      debug("Found %i in NAT", second->fd);
      socket_on_network_event(events, cur_time, socket);
    } else {
      debug("ERROR: Missing entry in NAT!?");
    }
  }

public:

#if defined(__ANDROID__)
  EventLoop(int tunnel_fd, int quit_fd, BlockList const& list, JNIEnv *jni_env, jobject jni_service): tunnel_fd(tunnel_fd), quit_fd(quit_fd), block(list), jni_env(jni_env), jni_service(jni_service) {
#else
  EventLoop(int tunnel_fd, int quit_fd, BlockList const& list): tunnel_fd(tunnel_fd), quit_fd(quit_fd), block(list) {
#endif
    stat = { 0 };

    epoll_fd = epoll_create(5);
    timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);

    fatal_guard(epoll_fd);
    fatal_guard(timer_fd);

#if defined(__ANDROID__)
    jni_service_class = (jni_env)->GetObjectClass(jni_service);
    report = jni_env->GetMethodID(jni_service_class,"report", "(JJJJJJJ)V");
    protect = jni_env->GetMethodID(jni_service_class,"protect", "(I)V");
#endif

    debug("Epoll FD: %i", epoll_fd);
  }

  void user_space_ip_proxy() {

    setup_timer();

    struct epoll_event events[MAX_EVENTS];

    set_nonblocking(tunnel_fd);

    debug("Preparing epoll listeners");
    listen_in(tunnel_fd);
    listen_in(quit_fd);
    listen_in(timer_fd);
    debug("Setup epoll listeners");

    struct timespec cur_time;
    struct timespec fin_time;

    while(true) {
      ssize_t event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
      clock_gettime(CLOCK_MONOTONIC, &cur_time);
      for(size_t i = 0; i < event_count; i++) {
        if (events[i].data.fd == tunnel_fd) {
          on_tun_in();
        } else if (events[i].data.fd == quit_fd) {
          debug("TODO: Appropriately tear it all down. Kill everything. Cleanup.");
          return;
        } else if (events[i].data.fd == timer_fd) {
          on_timer_in(cur_time);
        } else {
          on_network_event(events[i], cur_time);
        }
      }
      clock_gettime(CLOCK_MONOTONIC, &fin_time);
    }
  }

};

#endif
