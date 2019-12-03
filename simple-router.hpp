#ifndef SIMPLE_ROUTER_SIMPLE_ROUTER_HPP
#define SIMPLE_ROUTER_SIMPLE_ROUTER_HPP

#include "arp-cache.hpp"
#include "routing-table.hpp"
#include "core/protocol.hpp"
#include "core/interface.hpp"

#include "pox.hpp"

namespace simple_router {

class SimpleRouter
{
public:

  SimpleRouter();

  void
  handlePacket(const Buffer& packet, const std::string& inIface);

  /**
   * Call this method to send packet \p packt from the router on interface \p outIface
   */
  void
  sendPacket(const Buffer& packet, const std::string& outIface);

  /**
   * Load routing table information from \p rtConfig file
   */
  bool
  loadRoutingTable(const std::string& rtConfig);

  /**
   * Load local interface configuration
   */
  void
  loadIfconfig(const std::string& ifconfig);

  /**
   * Get routing table
   */
  const RoutingTable&
  getRoutingTable() const;

  /**
   * Get ARP table
   */
  const ArpCache&
  getArp() const;

  /**
   * Print router interfaces
   */
  void
  printIfaces(std::ostream& os);

  /**
   * Reset ARP cache and interface list (e.g., when mininet restarted)
   */
  void
  reset(const pox::Ifaces& ports);

  /**
   * Find interface based on interface's IP address
   */
  const Interface*
  findIfaceByIp(uint32_t ip) const;

  /**
   * Find interface based on interface's MAC address
   */
  const Interface*
  findIfaceByMac(const Buffer& mac) const;

  /**
   * Find interface based on interface's name
   */
  const Interface*
  findIfaceByName(const std::string& name) const;

private:
  ArpCache m_arp;
  RoutingTable m_routingTable;
  std::set<Interface> m_ifaces;
  std::map<std::string, uint32_t> m_ifNameToIpMap;

  friend class Router;
  pox::PacketInjectorPrx m_pox;
};

inline const RoutingTable&
SimpleRouter::getRoutingTable() const
{
  return m_routingTable;
}

inline const ArpCache&
SimpleRouter::getArp() const
{
  return m_arp;
}

} // namespace simple_router

#endif // SIMPLE_ROUTER_SIMPLE_ROUTER_HPP
