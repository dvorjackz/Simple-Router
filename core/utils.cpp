#include "utils.hpp"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

namespace simple_router {

uint16_t
cksum(const void* _data, int len)
{
  const uint8_t* data = reinterpret_cast<const uint8_t*>(_data);
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(const uint8_t* buf) {
  ethernet_hdr *ehdr = (ethernet_hdr *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(const uint8_t* buf) {
  ip_hdr *iphdr = (ip_hdr *)(buf);
  return iphdr->ip_p;
}


std::string
macToString(const Buffer& macAddr)
{
  char s[18]; // 12 digits + 5 separators + null terminator
  char sep = ':';

  // - apparently gcc-4.6 does not support the 'hh' type modifier
  // - std::snprintf not found in some environments
  //   https://redmine.named-data.net/issues/2299 for more information
  snprintf(s, sizeof(s), "%02x%c%02x%c%02x%c%02x%c%02x%c%02x",
           macAddr.at(0), sep, macAddr.at(1), sep, macAddr.at(2), sep,
           macAddr.at(3), sep, macAddr.at(4), sep, macAddr.at(5));

  return std::string(s);
}

std::string
ipToString(uint32_t ip)
{
  in_addr addr;
  addr.s_addr = ip;
  return ipToString(addr);
}

std::string
ipToString(const in_addr& address)
{
  char s[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, s, INET_ADDRSTRLEN) == nullptr) {
    throw std::runtime_error("Error while converting IP address to string");
  }
  return std::string(s);
}

/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(const uint8_t* addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

void print_addr_ip_int(uint32_t ip)
{
  in_addr addr;
  addr.s_addr = ntohl(ip);
  print_addr_ip(addr);
}

/* Prints out fields in Ethernet header. */
void
print_hdr_eth(const uint8_t* buf) {
  const ethernet_hdr *ehdr = (const ethernet_hdr *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(const uint8_t* buf) {
  const ip_hdr *iphdr = (const ip_hdr *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(const uint8_t* buf) {
  const icmp_hdr *hdr = reinterpret_cast<const icmp_hdr*>(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(const uint8_t* buf) {
  const arp_hdr *hdr = reinterpret_cast<const arp_hdr*>(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(hdr->arp_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(hdr->arp_pro));
  fprintf(stderr, "\thardware address length: %d\n", hdr->arp_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", hdr->arp_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(hdr->arp_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(hdr->arp_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(hdr->arp_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(hdr->arp_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(hdr->arp_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(const uint8_t* buf, uint32_t length) {

  /* Ethernet */
  size_t minlength = sizeof(ethernet_hdr);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(ip_hdr);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(ethernet_hdr));
    uint8_t ip_proto = ip_protocol(buf + sizeof(ethernet_hdr));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(icmp_hdr);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(arp_hdr);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(ethernet_hdr));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

void print_hdrs(const Buffer& buffer)
{
  print_hdrs(buffer.data(), buffer.size());
}


} // namespace simple_router
