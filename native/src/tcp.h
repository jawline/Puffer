#ifndef SECURITYWALL_TCP_H
#define SECURITYWALL_TCP_H
#include "socket.h"

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

  void return_tcp_rst(int tun_fd, const sockaddr_in& src, const sockaddr_in& dst) {
    char ipp[MTU];
    size_t pkt_sz = assemble_tcp_packet(ipp, MTU, 0, 0, nullptr, 0, src, dst, false, false, false, false, true);
    DROP_GUARD(pkt_sz > 0);
    write(tun_fd, ipp, pkt_sz);
  }
  
  void return_a_tcp_packet(int tun_fd, char* data, size_t len, const sockaddr_in& addr) {
  
    debug("Source: %s %i", inet_ntoa(in_addr { addr.sin_addr.s_addr }), addr.sin_port);
    debug("Dest: %s %i", inet_ntoa(in_addr { src.sin_addr.s_addr }), src.sin_port);
  
    char ipp[MTU];

    size_t pkt_sz = assemble_tcp_packet(ipp, MTU, us_seq, them_seq + 1, data, len, src, dst, false, false, true, false, false);
  
    if (len > 0) {
      us_seq += len;
    }

    if (pkt_sz <= 0) {
      return;
    }
  
    DROP_GUARD(pkt_sz > 0);
    write(tun_fd, ipp, pkt_sz);
    //tcp_bytes_in += len;
    // TODO: Increment TCP bytes in
  }

  void return_tcp_fin(int tun_fd) {
    char ipp[MTU];
    size_t pkt_sz = assemble_tcp_packet(ipp, MTU, us_seq++, them_seq + 1, NULL, 0, src, dst, false, false, true, true, false);
  
    DROP_GUARD(pkt_sz > 0);
    DROP_GUARD(write(tun_fd, ipp, pkt_sz) >= 0);
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

  virtual bool on_tun(int tun_fd, char* ip, char* proto, char* data, size_t data_size) {
    auto hdr = (struct ip*) ip;
    auto tcp_hdr = (struct tcphdr*) proto;
    auto ip_len = ntohs(hdr->len);
    auto tcp_seq = ntohl(tcp_hdr->seq);
    auto tcp_last_seq = them_seq;
    auto expected = us_ack;

    debug("TCP %i: Packet Length %u, TCP Seq: %u, Them Seq: %u, Expected Seq: %u", fd, ip_len, tcp_seq, tcp_last_seq, expected);

    if (tcp_hdr->rst) {
      debug("TCP %i: Broken stream (RST).", fd);
      return true;
    }

    if (tcp_hdr->syn) {
      debug("TCP %i: Repeat SYN", fd);
      return false;
    }

    if (!tcp_hdr->syn && tcp_hdr->ack && sent_syn_ack && !recv_first_ack) {
      debug("TCP %i: Socket ready for data", fd);
      recv_first_ack = true;
      // TODO: Fixme
      //listen_tcp(epoll_fd, fd);
    }

    // The rest of the process flow requires that we have a completed SYN-SYNACK-ACK connection sequence
    if (!recv_first_ack) {
      return false;
    }

    bool should_ack = false;

    // If there is data then process and acknowledge it
    if (data_size > 0) {

      // Decide if this packet is a repeat
      bool is_repeat = tcp_last_seq >= tcp_seq;
  
      if (is_repeat) {
        debug("TCP %i: Repeat packet", fd);
        return false;
      }

      them_seq += data_size;

      debug("TCP %i: DATA: Sequence: %u (New Expected: %u) Size: %lu", fd, tcp_seq, them_seq, data_size);

      /**
       * TODO: Fix Me
      if (first_packet) {
        char* hostname = nullptr;
        int result = parse_tls_header((uint8_t *) data_start, data_size, &hostname);
        if (hostname) {
          debug("SNI: Found %s", hostname);
          bool res = loop.block.block(hostname);
          if (res) {
            debug("SNI: Dropping connection\n");
            loop.blocked += 1;
            return_tcp_fin(ret, loop);
            return true;
          }
        }
        free(hostname);
        first_packet = false;
      }
      */

      // TODO: FixMe Update statistics
      // loop.tcp_bytes_out += data_size;

      // Send this on to the target
      if (send(fd, data, data_size, MSG_NOSIGNAL) < 0) {
        printf("Could not do TCP send\n");
        // TODO: Error handling on failure
      }

      should_ack = true;
    }

    if (tcp_hdr->fin) {
      them_seq += 1;
      shutdown(fd, SHUT_WR);
      debug("TCP %i: Client has shutdown write half of stream", fd);
      close_wr = true;
      should_ack = true;
    }

    // If we have sent a FIN then the final ACK will close the session
    if (tcp_hdr->ack && close_rd) {
      debug("TCP %i: Stream has acknowledged FIN", fd);
    }

    // Both sides are closed
    if (close_wr && ack_rd && close_rd) {
      debug("TCP %i: Both sides of the connection have closed and acknowledged", fd);
      // Clear up for dead session (This will handle removing the listener)
      // TODO: remove_fd_from_nat(loop, fd);
    }

    if (should_ack) {
      // Acknowledge the receipt by transmitting back a packet with 0 data but the ACK field set
      return_a_tcp_packet(tun_fd, nullptr, 0, dst);
    }

    return false;
  }

  virtual void on_sock(int sock_fd, char* data, size_t data_size) {}
};

#endif //SECURITYWALL_TCP_H
