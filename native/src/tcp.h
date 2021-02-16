#ifndef SECURITYWALL_TCP_H
#define SECURITYWALL_TCP_H

#include "log.h"
#include "packet.h"
#include "socket.h"
#include "tls.h"
#include "util.h"

#define NS_TO_MS(x) (((double)x) / (1000.0 * 1000.0))
#define S_TO_MS(x) (((double)x) / 1000.0)
#define AS_MS(x) (S_TO_MS(x.tv_sec) + NS_TO_MS(x.tv_nsec))

class TcpPart {
private:
public:
  uint32_t seq_start;
  size_t seq_len;
  char data[MTU];
  timespec packet_time;

  TcpPart(char *src_data, uint32_t seq_start, size_t len,
          timespec const &cur_time)
    : seq_start(seq_start), seq_len(len), packet_time(cur_time) {
    fatal_guard(len <= MTU);
    memcpy(data, src_data, len);
  }

  bool acknowledged(uint32_t ack_nr) const {
    return ack_nr > seq_start + seq_len;
  }

  inline bool should_retransmit(timespec const &cur_time) {
    double delta = AS_MS(cur_time) - AS_MS(packet_time);
    debug("Delta %lf %lf %lf\n", delta, AS_MS(cur_time), AS_MS(packet_time));
    if (delta > 1000.0) {
      debug("Delta %f", now_in_mil - time_in_mill);
      packet_time = cur_time;
      return true;
    }
    return false;
  }
};

class TcpStream : public Socket {
private:
  char stream_name[MAX_FQDN_LENGTH];

  uint32_t them_seq;
  uint32_t them_ack;

  uint32_t us_seq;
  uint32_t us_ack;

  bool sent_syn_ack;
  bool recv_first_ack;

  bool close_wr;
  timespec close_wr_time;

  bool close_rd;
  timespec close_rd_time;
  bool ack_rd;

  bool first_packet;

  size_t activity;
  std::deque<TcpPart> unacknowledged;

  inline bool retransmit_packet(int tun_fd, char *data, uint32_t us_seq_nr,
                                size_t len, bool syn, bool ack,
                                bool fin) const {
    debug("Source: %s %i", inet_ntoa(in_addr{dst.sin_addr.s_addr}),
          dst.sin_port);
    debug("Dest: %s %i", inet_ntoa(in_addr{src.sin_addr.s_addr}), src.sin_port);
    debug("Sequences %i:%i", us_seq, us_seq + len);

    char packet_buffer[MTU];
    size_t pkt_size =
      assemble_tcp_packet(packet_buffer, MTU, us_seq_nr, them_seq + 1, data,
                          len, dst, src, false, syn, ack, fin, false);

    DROP_GUARD_RET(pkt_size > 0, false);
    DROP_GUARD_RET(tun_write(tun_fd, packet_buffer, pkt_size) == pkt_size,
                   false);

    return true;
  }

  inline bool return_packet(int tun_fd, char *data, size_t len, bool syn,
                            bool ack, bool fin, timespec const &cur_time) {
    retransmit_packet(tun_fd, data, us_seq, len, syn, ack, fin);

    if (len > 0) {
      unacknowledged.push_back(TcpPart(data, us_seq, len, cur_time));
      us_seq += len;
    }

    return true;
  }

  inline bool return_a_tcp_packet(int tun_fd, char *data, size_t len,
                                  timespec const &cur_time) {
    return return_packet(tun_fd, data, len, false, true, close_rd, cur_time);
  }

public:
  TcpStream(int fd, sockaddr_in src, sockaddr_in dst, uint8_t proto,
            uint32_t them_seq_start)
    : Socket(fd, src, dst, proto) {

    them_seq = them_seq_start;
    them_ack = 0;

    us_seq = rand();
    us_ack = them_seq;

    sent_syn_ack = false;
    recv_first_ack = false;

    close_wr = false;
    close_rd = false;
    ack_rd = false;

    first_packet = true;

    debug("TCP: New Stream. Initial packet sequences: %u %u", them_seq,
          them_ack);
    debug("Source: %s %i", inet_ntoa(in_addr{src.sin_addr.s_addr}),
          src.sin_port);
    debug("Dest: %s %i", inet_ntoa(in_addr{dst.sin_addr.s_addr}), dst.sin_port);
  }

  inline bool should_block(char *data, size_t data_size,
                           BlockList const &block) {

    // Name the stream
    int result = parse_tls_header((uint8_t *)data, data_size, stream_name);

    // If there is not SNI in this stream use the IP address as the stream name
    // instead
    if (result <= 0) {
      inet_ntop(AF_INET, &dst, stream_name, MAX_FQDN_LENGTH);
    }

    log("TCP %i: stream named %s", fd, stream_name);

    return block.block(stream_name);
  }

  inline void shutdown_send(int tun_fd, int epoll_fd,
                            timespec const &cur_time) {
    if (!close_rd) {
      log("TCP %i: sent FIN byte and incremented sequence number", fd);
      close_rd = true;
      // Send the TCP FIN packet before incrementing the sequence number by 1
      // for the FIN
      return_a_tcp_packet(tun_fd, nullptr, 0, cur_time);
      close_rd_time = cur_time;
      stop_listen(epoll_fd, fd);
      us_seq += 1;
    }
  }

  bool on_tun(int tun_fd, int epoll_fd, char *ip, char *proto, char *data,
              size_t data_size, BlockList const &block, struct stats &stats,
              timespec const &cur_time) {

    activity++;

    auto hdr = (struct ip *)ip;
    auto tcp_hdr = (struct tcphdr *)proto;
    auto ip_len = ntohs(hdr->len);
    auto tcp_seq = ntohl(tcp_hdr->seq);
    them_ack = ntohl(tcp_hdr->ack_seq);
    auto expected = us_ack;

    debug("TCP %i: Packet Length %u, TCP Seq: %u, Them Seq: %u, Them Ack: %u "
          "Expected Seq: %u",
          fd, ip_len, tcp_seq, them_seq, them_ack, expected);

    if (tcp_hdr->rst) {
      log("TCP %i: Broken stream (RST).", fd);
      return true;
    }

    if (tcp_hdr->syn) {
      log("TCP %i: Repeat SYN", fd);
      return false;
    }

    if (tcp_hdr->ack && sent_syn_ack && !recv_first_ack) {
      log("TCP %i: Socket ready for data", fd);
      recv_first_ack = true;
      stop_listen(epoll_fd, fd);
      listen_tcp(epoll_fd, fd);
    }

    // The rest of the process flow requires that we have a completed
    // SYN-SYNACK-ACK connection sequence
    if (!recv_first_ack) {
      return false;
    }

    bool should_ack = false;
    bool is_out_of_order = tcp_seq != (them_seq + 1);

    if (is_out_of_order) {
      log("TCP %i: DATA: Out of order %u %u %u %u %zu", fd, tcp_seq, them_seq,
          us_seq, them_ack, unacknowledged.size());
    }

    // If there is data then process and acknowledge it
    if (data_size > 0 && !is_out_of_order) {

      them_seq += data_size;

      debug("TCP %i: DATA: Sequence: %u (New Expected: %u) Size: %zu", fd,
            tcp_seq, them_seq, data_size);

      if (first_packet) {
        if (should_block(data, data_size, block)) {
          log("SNI: Dropping connection");
          stats.blocked += 1;
          shutdown_send(tun_fd, epoll_fd, cur_time);
        }
        first_packet = false;
      }

      // Send this on to the target
      size_t remaining = data_size;
      while (remaining > 0) {
        ssize_t rd = send(fd, data, remaining, MSG_NOSIGNAL);
        // debug("Send %li bytes via TCP", rd);
        if (rd < 0) {

          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
          }

          // TODO: ERROR!
          debug("Broken outbound stream %i", errno);
          shutdown_send(tun_fd, epoll_fd, cur_time);
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
      log("TCP %i: Client has shutdown write half of stream %u %u %i", fd,
          us_seq, them_ack, close_rd);
      close_wr = true;
      close_wr_time = cur_time;
      should_ack = true;
    }

    // If we have sent a FIN then the final ACK will close the session
    // If they have acked up until the last byte of real data we close
    if (tcp_hdr->ack && close_rd && !ack_rd && them_ack >= us_seq) {
      log("TCP %i: Stream has acknowledged FIN %u %u %u with %zu remaining", fd,
          tcp_seq, them_ack, us_seq, unacknowledged.size());
      ack_rd = true;
    }

    // Both sides are closed
    if (close_wr && ack_rd && close_rd) {
      // Return true -> remove the stream from NAT
      log("TCP %i: Both sides of the connection have closed and acknowledged",
          fd);
      return_a_tcp_packet(tun_fd, nullptr, 0, cur_time);
      return true;
    }

    if (should_ack) {
      // Acknowledge the receipt by transmitting back a packet with 0 data but
      // the ACK field set
      return_a_tcp_packet(tun_fd, nullptr, 0, cur_time);
    }

    return false;
  }

  bool before_tun(int tun_fd, int epoll_fd) { return false; }

  bool after_tun(int tun_fd, int epoll_fd, timespec const &cur_time) {

    // Remove any TCP segments that have been completely acknowledged
    while (unacknowledged.size() &&
           unacknowledged.front().acknowledged(them_ack)) {
      debug("Acknowledged %i", unacknowledged.front().seq_start);
      unacknowledged.pop_front();
    }

    if (unacknowledged.size()) {
      size_t done = 0;

      for (auto segment : unacknowledged) {
        if (segment.should_retransmit(cur_time)) {
          retransmit_packet(tun_fd, segment.data, segment.seq_start,
                            segment.seq_len, false, true, close_rd);
          done++;
        }
      }

      // If we had anything to say and we are closing then send a fin too
      if (done) {
        log("Sent %zu retransmits", done);
        if (close_rd && them_ack != (us_seq + 1)) {
          retransmit_packet(tun_fd, 0, us_seq - 1, 0, false, true, close_rd);
        }
      }
    }

    if (close_rd && AS_MS(close_rd_time) > CLOSING_TIMEOUT) {
      log("TCP %i: timeout while waiting to close (close rd)", fd);
      return true;
    }

    return false;
  }

  bool on_data(int tun_fd, int epoll_fd, char *data, size_t data_size,
               struct stats &stats, timespec const &cur_time) {
    debug("TCP: %i Returning a packet", fd);
    // log("Returning %30s", data);
    return_a_tcp_packet(tun_fd, data, data_size, cur_time);
    stats.tcp_bytes_in += data_size;
    return false;
  }

  bool on_sock(int tun_fd, int epoll_fd, int events, struct stats &stats,
               timespec const &cur_time) {

    if (events & EPOLLOUT) {
      debug("TCP Connected - it's TIME TO SEND A SYN-ACK");
      debug("SYN-ACK numbers %u %u", us_seq, them_seq + 1);

      DROP_GUARD_RET(
        return_packet(tun_fd, nullptr, 0, true, true, false, cur_time), true);
      us_seq++;

      // After sending a SYN-ACK we expect an ACK. Don't touch the REMOTE SOCKET
      // until then
      sent_syn_ack = true;
      stop_listen(epoll_fd, fd);
    }

    if (events & (EPOLLHUP | EPOLLRDHUP)) {
      debug(
        "TCP %i: Upstream closed. Generating FIN with SYN-ACK numbers %u %u",
        fd, us_seq, them_seq + 1);

      // On the next ACK we actually clean up since we expect an ACK before the
      // session is fully closed
      // TODO: Add a CLOSING timeout of 30s
      shutdown_send(tun_fd, epoll_fd, cur_time);
    }

    return false;
  }

  static inline void return_tcp_rst(int tun_fd, const sockaddr_in &src,
                                    const sockaddr_in &dst) {
    char ipp[MTU];
    size_t pkt_sz = assemble_tcp_packet(ipp, MTU, 0, 0, nullptr, 0, dst, src,
                                        false, false, false, false, true);
    DROP_GUARD(pkt_sz > 0);
    DROP_GUARD(tun_write(tun_fd, ipp, pkt_sz) >= 0);
  }
};

#endif // SECURITYWALL_TCP_H
