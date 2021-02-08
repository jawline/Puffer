#ifndef _GR
#define _GR
#include "network.h"
#include "socket.h"

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

  std::map<ip_port_protocol, std::shared_ptr<Socket>> outbound_nat;
  std::map<int, std::shared_ptr<Socket>> inbound_nat;

  BlockList block;

#if defined(__ANDROID__)
  JNIEnv *env;
  jobject swall;
#endif

  inline void register_udp(ip_port_protocol const& id, std::shared_ptr<Socket> new_entry) {
    udp_total += 1;
    outbound_nat[id] = new_entry;
    inbound_nat[new_entry->fd] = new_entry;
    listen_in(new_entry->fd);
  }

  inline void register_tcp(ip_port_protocol const& id, std::shared_ptr<Socket> new_entry) {
    tcp_total += 1;
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

} event_loop_t;

void user_space_ip_proxy(int tunnel_fd, event_loop_t loop);

#endif
