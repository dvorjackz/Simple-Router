#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << "Routing table: " << std::endl;
  std::cerr << getRoutingTable() << std::endl;

  // Cast packet from char vector into ethernet header struct
  const uint8_t *buf = packet.data();
  ethernet_hdr *ehdr =  (ethernet_hdr *) buf;
  const uint16_t packet_type = ethertype(buf);

  std::cerr << "----------------------------- Received packet! Start of headers: " << std::endl;
  print_hdrs(packet);
  std::cerr << "----------------------------- Received packet! End of headers. " << std::endl << std::endl;

  // ARP packet
  if (packet_type == ethertype_arp) {
    const arp_hdr *arphdr = (arp_hdr *) (packet.data() + sizeof(ethernet_hdr));
    if (ntohs(arphdr->arp_op) == arp_op_request) {

      fprintf(stderr, "Received an ARP request.\n");

      // Construct ARP response to be sent to host from scratch
      auto response_len = (sizeof(ethernet_hdr) + sizeof(arp_hdr))/sizeof(unsigned char);
      Buffer response(response_len);
      // We work on wres, because it is easier to work w/ an array, then move it into res
      uint8_t w_response[response_len];

      // Format the ethernet header of the response
      ethernet_hdr *response_eth_hdr = (ethernet_hdr *) w_response;
      // Send from interface that picked up the packet
      memcpy(response_eth_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
      // Send back to the host
      memcpy(response_eth_hdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
      response_eth_hdr->ether_type = htons(ethertype_arp);

      // Format the ARP header of the response
      arp_hdr *response_arp_hdr = (arp_hdr *) (w_response + sizeof(ethernet_hdr));
      response_arp_hdr->arp_hrd = htons(arp_hrd_ethernet);
      response_arp_hdr->arp_pro = htons(ethertype_ip);
      response_arp_hdr->arp_hln = ETHER_ADDR_LEN;
      // There are 4 ensuing addresses
      response_arp_hdr->arp_pln = 4;
      response_arp_hdr->arp_op = htons(arp_op_reply);
      memcpy(response_arp_hdr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
      response_arp_hdr->arp_sip = iface->ip;
      memcpy(response_arp_hdr->arp_tha, ehdr->ether_shost, ETHER_ADDR_LEN);
      response_arp_hdr->arp_tip = arphdr->arp_sip;

      // Move array into Buffer
      memcpy(&response[0], &w_response[0], response_len);

      std::cerr << "----------------------------- Sending ARP response! Start of headers: " << std::endl;
      print_hdrs(response);
      std::cerr << "----------------------------- Sent ARP response! End of headers. " << std::endl << std::endl;

      sendPacket(response, iface->name);
    }
    else if (ntohs(arphdr->arp_op) == arp_op_reply) {
      
      fprintf(stderr, "Received an ARP response.\n");
      // Check if ARP is addressed to this router
      if (arphdr->arp_tip == iface->ip) {
        Buffer mac_addr(ETHER_ADDR_LEN);
        memcpy(&mac_addr[0], &(arphdr->arp_sha)[0], ETHER_ADDR_LEN);
        std::shared_ptr<ArpRequest> res = m_arp.insertArpEntry(mac_addr, arphdr->arp_sip);
        m_arp.removeRequest(res);

        // Add the queued packets associated with the now resolved IP address
        if (res != nullptr) {
          for (auto queued_packet : res->packets) {
            Buffer send = queued_packet.packet;
            ethernet_hdr *send_ehdr = (ethernet_hdr *) (send.data());

            // Update ethernet headerswith correct dest mac address
            memcpy(send_ehdr->ether_dhost, mac_addr.data(), ETHER_ADDR_LEN);
            memcpy(send_ehdr->ether_shost, findIfaceByName(queued_packet.iface)->addr.data(), ETHER_ADDR_LEN);
            send_ehdr->ether_type = htons(ethertype_ip);

            // Update ip headers by decreasing TTL and recomputing checksum
            ip_hdr *send_iphdr = (ip_hdr *) (send.data() + sizeof(ethernet_hdr));
            (send_iphdr->ip_ttl)--;
            send_iphdr->ip_sum = 0;
            uint16_t new_cksum = cksum((void *) send_iphdr, sizeof(ip_hdr));
            send_iphdr->ip_sum = new_cksum;

            std::cerr << "----------------------------- Sending queued packet! Start of headers: " << std::endl;
            print_hdrs(send);
            std::cerr << "----------------------------- Sent queued packet! End of headers. " << std::endl << std::endl;
            sendPacket(send, queued_packet.iface);
          }
        }
      }
    }
  }
  // IPv4 packet
  else if (packet_type == ethertype_ip) {
    fprintf(stderr, "It's an IPv4 packet.\n");
    ip_hdr *iphdr = (ip_hdr *) (buf + sizeof(ethernet_hdr));

    // Temporarily set ip_sum to 0, becuase the host calculated the checksum with this field as -
    uint16_t original_cksum = iphdr->ip_sum;
    iphdr->ip_sum = 0;
    if (cksum((void *) iphdr, sizeof(ip_hdr)) != original_cksum) {
      fprintf(stderr, "IP header checksum integrity was not maintained.\n");
      return;
    }
    iphdr->ip_sum = original_cksum;
    // 20 = IP headers, 14 = ethernet headers, 34 = IP + ethernet headers
    if (ntohs(iphdr->ip_len) < sizeof(ip_hdr)) {
      fprintf(stderr, "Packet size of %d is less than minimum.\n", sizeof(buf));
      return;
    }
    // Check if TTL has expired
    if (iphdr->ip_ttl <= 0)
		{
			std::cerr << "Packet TTL has expired; dropped.\n" << std::endl;
			return;
		}

    fprintf(stderr, "Passed checksum and packet length tests!\n");

    // The parameter for findIfaceByMac is a Buffer
    Buffer src_mac(ETHER_ADDR_LEN);
    memcpy(&src_mac[0], &(ehdr->ether_dhost)[0], ETHER_ADDR_LEN);
    // If desination mac address is not that of the interface, drop the packet
    if (findIfaceByMac(src_mac) == nullptr) {
      fprintf(stderr, "Packet was not addressed to the router. (Not the same mac addresses)\n");
      return;
    }
    else {
      // Packet is destined for the router (final destination ip address is that of a router interface)
      uint32_t ip_dest = iphdr->ip_dst;
      if (findIfaceByIp(iphdr->ip_dst) != nullptr) {
        // TODO: If there's an ICMP payload, do stuff. Else, drop the packet
        fprintf(stderr, "Packet was addressed to the router. (Final desination of IP packet was that of the router)\n");

        auto icmp_min_len = sizeof(ethernet_hdr) + sizeof(ip_hdr);
        icmp_hdr *icmphdr = (icmp_hdr *) (packet.data() + icmp_min_len);
        auto icmp_packet_len = packet.size() - icmp_min_len;

        if (iphdr->ip_p == ip_protocol_icmp && icmphdr->icmp_type == 8) {
          Buffer echo_reply = packet;

          // Edit ethernet header 
          ethernet_hdr *ehdr_echo_reply = (ethernet_hdr *) echo_reply.data();
          memcpy(ehdr_echo_reply->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
          memcpy(ehdr_echo_reply->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
          ehdr_echo_reply->ether_type = htons(ethertype_ip);

          // Edit IP header
          ip_hdr *iphdr_echo_reply = (ip_hdr *) (echo_reply.data() + sizeof(ethernet_hdr));
          auto temp = iphdr_echo_reply->ip_src;
          iphdr_echo_reply->ip_src = iphdr_echo_reply->ip_dst;
          iphdr_echo_reply->ip_dst = temp;
          iphdr_echo_reply->ip_ttl = 64;
          iphdr_echo_reply->ip_sum = 0;
          iphdr_echo_reply->ip_sum = cksum(iphdr_echo_reply, sizeof(ip_hdr));

          // Deal with ICMP header
          icmp_hdr *icmp_echo_reply = (icmp_hdr *) (echo_reply.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
          memcpy(icmp_echo_reply, icmphdr, icmp_packet_len);

          // First verify the checksum
          uint16_t original_icmp_cksum = icmphdr->icmp_sum;
          icmphdr->icmp_sum = 0;
          if (cksum(icmphdr, icmp_packet_len) != original_icmp_cksum) {
            fprintf(stderr, "ICMP checksum integrity was not maintained.\n");
            return;
          }

          icmp_echo_reply->icmp_type = 0;
          icmp_echo_reply->icmp_code = 0;
          icmp_echo_reply->icmp_sum = 0;
          icmp_echo_reply->icmp_sum = cksum(icmp_echo_reply, icmp_packet_len);

          std::cerr << "----------------------------- Sending ICMP echo reply! Start of headers: " << std::endl;
          print_hdrs(echo_reply);
          std::cerr << "----------------------------- Sent ICMP echo reply! End of headers. " << std::endl << std::endl;
          sendPacket(echo_reply, iface->name);
        }
      }
      // Regular IPv4 packet with a host destination
      else {
        // Find ip with longest matching prefix
        fprintf(stderr, "Looking up destination ip with longest matching prefix alg: ");
        std::cerr << ipToString(ip_dest) << "..." << std::endl;
        RoutingTableEntry routing_entry = m_routingTable.lookup(ip_dest);

        // Check if arp entry exists for longest-matched-prefix ip
        std::shared_ptr<ArpEntry> arpentry = m_arp.lookup(routing_entry.gw);
        if (arpentry == nullptr) {
          fprintf(stderr, "No ARP entry exists for the next hop IP address. Sending ARP request to locate:\n");

          // Queue up the packet while the router sends ARP requests to find the dest mac address
          m_arp.queueRequest(routing_entry.gw, packet, routing_entry.ifName);
        } 
        else {
          fprintf(stderr, "Found ARP entry for the next hop IP address!\n");
          memcpy(ehdr->ether_dhost, arpentry->mac.data(), ETHER_ADDR_LEN);
			    memcpy(ehdr->ether_shost, findIfaceByName(routing_entry.ifName)->addr.data(), ETHER_ADDR_LEN);

          // Decrement Time To Live
          (iphdr->ip_ttl)--;

          // Recompute checksum
          iphdr->ip_sum = 0;
          uint16_t new_cksum = cksum((void *) iphdr, sizeof(ip_hdr));
          iphdr->ip_sum = new_cksum;

          std::cerr << "----------------------------- Forwarding IPv4 packet! Start of headers: " << std::endl;
          print_hdrs(packet);
          std::cerr << "----------------------------- Forwarding IPv4 packet! End of headers. " << std::endl;
          
          sendPacket(packet, routing_entry.ifName);
        }
      }
    }
  }
  // Neither ARP nor IPv4
  else {
    fprintf(stderr, "Received packet, but the packet type was not IPv4 or ARP.\n");
    return;
  }
  // std::cout << "Destination: " << macToString((*ehdr).ether_dhost) << std::endl;
  // std::cout << "Source: " << macToString((*ehdr).ether_shost) << std::endl;

}
////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
