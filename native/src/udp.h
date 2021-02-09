#ifndef SECURITYWALL_UDP_H
#define SECURITYWALL_UDP_H
#include "packet.h"
#include "socket.h"
#include "network.h"
#include "util.h"

class UdpStream: public Socket {
private:
public:

    UdpStream(int fd, sockaddr_in src, sockaddr_in dst, uint8_t proto): Socket(fd, src, dst, proto) {}

    bool on_tun(int tun_fd, int epoll_fd, char* ip, char* proto, char* data, size_t data_size, BlockList const& block, struct stats& stats) {
      auto ip_hdr = (struct ip*) ip;
      auto udp_hdr = (struct udphdr*) proto;

      stats.udp_bytes_out += data_size;

      // Now proxy the UDP packet to the destination
      // Don't fuss about retransmits, it's UDP
      auto dst = lookup_dst_udp(ip_hdr, udp_hdr);
      sendto(fd, data, data_size, 0, (struct sockaddr*) &dst, sizeof(dst));

      return false;
    }

    bool on_data(int tun_fd, int epoll_fd, char* data, size_t data_size, struct stats& stats) {
      char ipp[MTU];

      ssize_t pkt_sz = assemble_udp_packet(ipp, MTU, data, data_size, src, dst);
      DROP_GUARD_RET(pkt_sz > 0, false);

      // Don't fret about failure to return data - it's UDP
      write(tun_fd, ipp, pkt_sz);
      stats.udp_bytes_in += data_size;
      return false;
    }

    bool on_sock(int tun_fd, int epoll_fd, int events, struct stats& stats) {
      return false;
    }
};


#endif //SECURITYWALL_UDP_H
