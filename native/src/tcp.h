#ifndef SECURITYWALL_TCP_H
#define SECURITYWALL_TCP_H
#include "socket.h"
#include "tls.h"

static inline ssize_t tun_write(int tun_fd, char* pkt, size_t pkt_sz) {
  ssize_t r;
  while (true) {
    r = write(tun_fd, pkt, pkt_sz);
    if (r == -1) {
        if (errno == EAGAIN) {
            log("TCP: TUN Write blocked");
        } else {
            log("TCP: Tun write %i", errno);
        }
    } else {
        break;
    }
  }
  return r;
}

class TcpStream: public Socket {
private:
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

  void return_a_tcp_packet(int tun_fd, char* data, size_t len, const sockaddr_in& addr) {

    debug("Source: %s %i", inet_ntoa(in_addr { addr.sin_addr.s_addr }), addr.sin_port);
    debug("Dest: %s %i", inet_ntoa(in_addr { src.sin_addr.s_addr }), src.sin_port);

    char ipp[MTU];
    size_t pkt_sz = assemble_tcp_packet(ipp, MTU, us_seq, them_seq + 1, data, len, dst, src, false, false, true, false, false);

    us_seq += len;

    DROP_GUARD(pkt_sz > 0);

    // TODO: This failing is fatal for the stream
    // But we currently won't fail gracefully
    DROP_GUARD(tun_write(tun_fd, ipp, pkt_sz) == pkt_sz);
  }

  void return_tcp_fin(int tun_fd) {

    char ipp[MTU];
    size_t pkt_sz = assemble_tcp_packet(ipp, MTU, us_seq++, them_seq + 1, NULL, 0, dst, src, false, false, true, true, false);
    DROP_GUARD(pkt_sz > 0);

    // TODO: This failing is fatal for the stream
    // But we currently won't fail gracefully
    DROP_GUARD(tun_write(tun_fd, ipp, pkt_sz) == pkt_sz);
  }

public:

  TcpStream(int fd, sockaddr_in src, sockaddr_in dst, uint8_t proto, uint32_t them_seq_start): Socket(fd, src, dst, proto) {

    them_seq = them_seq_start;
    them_ack = 0;

    us_seq = rand();
    us_ack = them_seq;

    sent_syn_ack = false;
    recv_first_ack = false;

    close_wr = false;
    close_rd = false;
    ack_rd = false;

    first_packet = false;

    debug("TCP: New Stream. Initial packet sequences: %u %u", them_seq, them_ack);
    debug("Source: %s %i", inet_ntoa(in_addr { src.sin_addr.s_addr }), src.sin_port);
    debug("Dest: %s %i", inet_ntoa(in_addr { dst.sin_addr.s_addr }), dst.sin_port);
  }

  static inline bool should_block(char* data, size_t data_size, BlockList const& block) {
    char* hostname = nullptr;
    int result = parse_tls_header((uint8_t *) data, data_size, &hostname);
    bool will_block = false;
    if (hostname) {
      debug("SNI: Found %s", hostname);
      will_block = block.block(hostname);
    }
    free(hostname);
    return will_block;
  }

  bool on_tun(int tun_fd, int epoll_fd, char* ip, char* proto, char* data, size_t data_size, BlockList const& block, struct stats& stats) {
    auto hdr = (struct ip*) ip;
    auto tcp_hdr = (struct tcphdr*) proto;
    auto ip_len = ntohs(hdr->len);
    auto tcp_seq = ntohl(tcp_hdr->seq);
    auto expected = us_ack;

    debug("TCP %i: Packet Length %u, TCP Seq: %u, Them Seq: %u, Expected Seq: %u", fd, ip_len, tcp_seq, them_seq, expected);

    if (tcp_hdr->rst) {
      log("TCP %i: Broken stream (RST).", fd);
      return true;
    }

    if (tcp_hdr->syn) {
      log("TCP %i: Repeat SYN", fd);
      return false;
    }

    if (!tcp_hdr->syn && tcp_hdr->ack && sent_syn_ack && !recv_first_ack) {
      log("TCP %i: Socket ready for data", fd);
      recv_first_ack = true;
      listen_tcp(epoll_fd, fd);
    }

    // The rest of the process flow requires that we have a completed SYN-SYNACK-ACK connection sequence
    if (!recv_first_ack) {
      return false;
    }

    bool should_ack = false;

    // If there is data then process and acknowledge it
    if (data_size > 0) {

      // Decide if this packet is a repeat
      bool is_out_of_order = tcp_seq != (them_seq + 1);

      if (is_out_of_order) {
        log("TCP %i: Out of order %u:%u", fd, tcp_seq, them_seq);
        return false;
      }

      them_seq += data_size;

      log("TCP %i: DATA: Sequence: %u (New Expected: %u) Size: %zu", fd, tcp_seq, them_seq, data_size);

      if (first_packet) {
        if (should_block(data, data_size, block)) {
            log("SNI: Dropping connection\n");
            stats.blocked += 1;
            return_tcp_fin(tun_fd);
            return true;
        }
      }

      //log("%20s", data);
      //log("ED");

      // Send this on to the target
      size_t remaining = data_size;
      while (remaining > 0) {
        ssize_t rd = send(fd, data, remaining, MSG_NOSIGNAL);
        //debug("Send %li bytes via TCP", rd);
        if (rd < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
          }
          // TODO: ERROR!
          debug("Broken outbound stream %i", errno);
          return_tcp_fin(tun_fd);
          close_rd = true;
          break;
        }
        remaining -= rd;
        data += rd;
      }

      stats.tcp_bytes_out += data_size;
      should_ack = true;
    }

    if (tcp_hdr->fin) {
      them_seq += 1;
      shutdown(fd, SHUT_WR);
      log("TCP %i: Client has shutdown write half of stream", fd);
      close_wr = true;
      should_ack = true;
    }

    // If we have sent a FIN then the final ACK will close the session
    if (tcp_hdr->ack && close_rd) {
      log("TCP %i: Stream has acknowledged FIN", fd);
      ack_rd = true;
      should_ack = true;
    }

    // Both sides are closed
    if (close_wr && ack_rd && close_rd) {
      // Return true -> remove the stream from NAT
      log("TCP %i: Both sides of the connection have closed and acknowledged", fd);
      //return true;
    }

    if (should_ack) {
      // Acknowledge the receipt by transmitting back a packet with 0 data but the ACK field set
      return_a_tcp_packet(tun_fd, nullptr, 0, dst);
    }

    return false;
  }

  bool on_data(int tun_fd, int epoll_fd, char* data, size_t data_size, struct stats& stats) {
    debug("TCP: %i Returning a packet", fd);
    //log("Returning %30s", data);
    return_a_tcp_packet(tun_fd, data, data_size, dst);
    stats.tcp_bytes_in += data_size;
    return false;
  }

  bool on_sock(int tun_fd, int epoll_fd, int events, struct stats& stats) {

    if (events & EPOLLOUT) {
      debug("TCP Connected - it's TIME TO SEND A SYN-ACK");

      char ipp[1500];
      ssize_t ipp_sz;

      debug("SYN-ACK numbers %u %u", us_seq, them_seq + 1);
      size_t pkt_sz = assemble_tcp_packet(ipp, 1500, us_seq++, them_seq + 1, NULL, 0, dst, src, false, true, true, false, false);
      DROP_GUARD_RET(pkt_sz > 0, true);

      // This failing is fatal for the stream
      DROP_GUARD_RET(tun_write(tun_fd, ipp, pkt_sz) == pkt_sz, true);

      // After sending a SYN-ACK we expect an ACK. Don't touch the REMOTE SOCKET until then
      stop_listen(epoll_fd, fd);
      sent_syn_ack = true;
    }

    if (events & (EPOLLHUP | EPOLLRDHUP)) {
      debug("TCP closed - it's time to SEND A FIN");

      // Fabricate a FIN
      char ipp[1500];
      ssize_t ipp_sz;

      debug("TCP %i: Upstream closed. Generating FIN with SYN-ACK numbers %u %u", fd, us_seq, them_seq + 1);
      return_tcp_fin(tun_fd);

      // On the next ACK we actually clean up since we expect an ACK before the session is fully closed
      close_rd = true;
      stop_listen(epoll_fd, fd); 
    }

    return false;
  }

  static inline void return_tcp_rst(int tun_fd, const sockaddr_in& src, const sockaddr_in& dst) {
    char ipp[MTU];
    size_t pkt_sz = assemble_tcp_packet(ipp, MTU, 0, 0, nullptr, 0, dst, src, false, false, false, false, true);
    DROP_GUARD(pkt_sz > 0);
    DROP_GUARD(write(tun_fd, ipp, pkt_sz) >= 0); // TODO: Deal with this failure!!
  }
};

#endif //SECURITYWALL_TCP_H
