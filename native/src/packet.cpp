#include "packet.h"
#include "checksum.h"
#include "log.h"

void assemble_ip_header(ip* ip_hdr, uint8_t protocol, const sockaddr_in& sender, const sockaddr_in& return_addr, size_t packet_len) {
  ip_hdr->ihl = 5;
  ip_hdr->version = 4;
  ip_hdr->tos = 0;
  ip_hdr->len = htons(packet_len);
  ip_hdr->id = rand();
  ip_hdr->flags = 0;
  ip_hdr->frag_offset = 0;
  ip_hdr->ttl = 64;
  ip_hdr->proto = protocol;
  ip_hdr->saddr = sender.sin_addr.s_addr;
  ip_hdr->daddr = return_addr.sin_addr.s_addr;

  // Calculate the checksum
  // Must be zero to start
  ip_hdr->csum = 0;
  ip_hdr->csum = wrapsum(checksum((uint8_t *) ip_hdr, ip_hdr->ihl << 2, 0));
  //debug("CSUM: %x", ip_hdr->csum);
  //debug("Return Address: %i", return_addr.sin_addr.s_addr);
  //debug("Packet Length: %li (%i)", packet_len, ip_hdr->len);
}

void assemble_udp_header(const ip* ip, udphdr* udp, size_t datagram_contents_size, const sockaddr_in& sender, const sockaddr_in& return_addr) {
  udp->source = sender.sin_port;
  udp->dest = return_addr.sin_port;
  udp->len = htons(sizeof(udphdr) + datagram_contents_size);

  // Calculate the UDP checksum
  // Must be zero to start
  udp->check = 0;

  uint16_t sum = wrapsum(checksum((unsigned char *)udp, sizeof(*udp),
      checksum((unsigned char *) (udp + 1), datagram_contents_size, checksum((unsigned char *)&ip->saddr,
      2 * sizeof(ip->saddr),
      IPPROTO_UDP + (uint32_t)ntohs(udp->len)))));

  udp->check = sum;

  //debug("UDP CHECK: %x\n", udp->check);
}

uint16_t checksum(const ip* ip, uint8_t* header, size_t header_len, uint8_t* data, size_t data_len, uint8_t proto, uint32_t len) {
  return wrapsum(checksum((unsigned char *)header, header_len,
      checksum(data, data_len, checksum((unsigned char *)&ip->saddr,
      2 * sizeof(ip->saddr),
      proto + len))));
}

void assemble_tcp_header(const ip* ip, tcphdr* tcp, uint32_t seq, uint32_t ack, size_t datagram_contents_size, const sockaddr_in& sender, const sockaddr_in& return_addr, bool pshf, bool synf, bool ackf, bool finf, bool rstf) {

  memset(tcp, 0, sizeof(*tcp));

  tcp->source = sender.sin_port;
  tcp->dest = return_addr.sin_port;
  tcp->doff = 5;
  tcp->seq = htonl(seq);
  tcp->ack_seq = htonl(ack);
  tcp->window = 65535;

  //debug("SEQ: %u (%u) ACK: %u (%u)", seq, tcp->seq, ack, tcp->ack);

  if (pshf) { tcp->psh = 1; }
  if (synf) { tcp->syn = 1; }
  if (ackf) { tcp->ack = 1; }
  if (finf) { tcp->fin = 1; }
  if (rstf) { tcp->rst = 1; }

  // Calculate the UDP checksum
  // Must be zero to start
  tcp->check = 0;

  uint16_t sum = wrapsum(checksum((unsigned char *)tcp, sizeof(*tcp),
      checksum((unsigned char *) (tcp + 1), datagram_contents_size, checksum((unsigned char *)&ip->saddr,
      2 * sizeof(ip->saddr),
      ip->proto + (uint32_t)(ntohs(ip->len) - sizeof(*ip))))));

  tcp->check = sum;

  //debug("TCP CHECK: %x", tcp->check);
}

ssize_t assemble_udp_packet(char* dst, size_t mtu, char* data, size_t len, const sockaddr_in& return_addr, const sockaddr_in& from) {

  // How big will this UDP packet be
  size_t datagram_size = sizeof(udphdr) + len;
  size_t packet_size = sizeof(ip) + datagram_size;
  DROP_GUARD_INT(datagram_size <= mtu);

  // Find offsets in our constructed packet
  ip* ip_hdr = (ip*) dst;
  udphdr* udp = (udphdr*) (dst + sizeof(ip));
  char* contents = dst + sizeof(ip) + sizeof(udphdr);

  // Copy in the data first so that checksumming works 
  memcpy(contents, data, len);

  // Now make the headers and do checksums
  assemble_ip_header(ip_hdr, IPPROTO_UDP, from, return_addr, packet_size);
  assemble_udp_header(ip_hdr, udp, len, from, return_addr);

  // Now this packet is ready to write back to the TUN device
  return packet_size;
}

ssize_t assemble_tcp_packet(char* dst, size_t mtu, uint32_t seq, uint32_t ack, char* data, size_t len, const sockaddr_in& return_addr, const sockaddr_in& from, bool pshf, bool synf, bool ackf, bool finf, bool rstf) {

  // How big will this UDP packet be
  size_t datagram_size = sizeof(tcphdr) + len;
  size_t packet_size = sizeof(ip) + datagram_size;
  DROP_GUARD_INT(datagram_size <= mtu);

  // Find offsets in our constructed packet
  ip* ip_hdr = (ip*) dst;
  tcphdr* tcp = (tcphdr*) (dst + sizeof(ip));
  char* contents = dst + sizeof(ip) + sizeof(tcphdr);

  // Copy in the data first so that checksumming works 
  memcpy(contents, data, len);

  // Now make the headers and do checksums
  assemble_ip_header(ip_hdr, IPPROTO_TCP, from, return_addr, packet_size);
  assemble_tcp_header(ip_hdr, tcp, seq, ack, len, from, return_addr, pshf, synf, ackf, finf, rstf);

  return packet_size;
}
