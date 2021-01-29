#ifndef _PACKET
#define _PACKET
#include "general.h"

/**
 * Assemble an IP header for a packet returning to the device tun device.
 * We need the address we received the packet from as well as the return address (worked out by our userspace NAT).
 * This function also takes care of your checksum.
 */
void assemble_ip_header(ip* ip_hdr, uint8_t protocol, const sockaddr_in* sender, const msg_return* return_addr, size_t packet_len);

/**
 * Assemble the UDP header given the IP header (should already be assembled and checksummed).
 * We need the sender and return address to set the ports in the datagram header.
 * We expect the datagram contents to be placed directly after the UDP header in memory, and this will be used in checksumming.
 * This function also takes care of your checksum.
 */
void assemble_udp_header(const ip* ip, udphdr* udp, size_t datagram_contents_size, const sockaddr_in* sender, const msg_return* return_addr);

/**
 * Assemble a UDP packet into the dst packet up to MTU of bytes and return the size (will fail if datagram size >= supplied mtu)
 * Will handle IP and UDP header creation and checksumming, just feed it bytes.
 */
ssize_t assemble_udp_packet(char* dst, size_t mtu, char* data, size_t len, msg_return* return_addr, sockaddr_in* from);

#endif
