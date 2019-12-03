#ifndef SIMPLE_ROUTER_ROUTING_TABLE_HPP
#define SIMPLE_ROUTER_ROUTING_TABLE_HPP

#include "core/protocol.hpp"

#include <list>

namespace simple_router {

struct RoutingTableEntry
{
  uint32_t dest;
  uint32_t gw;
  uint32_t mask;
  std::string ifName;
};

class RoutingTable
{
public:

  RoutingTableEntry
  lookup(uint32_t ip) const;

  bool
  load(const std::string& file);

  void
  addEntry(RoutingTableEntry entry);

private:
  std::list<RoutingTableEntry> m_entries;

  friend std::ostream&
  operator<<(std::ostream& os, const RoutingTable& table);
};

std::ostream&
operator<<(std::ostream& os, const RoutingTableEntry& entry);

std::ostream&
operator<<(std::ostream& os, const RoutingTable& table);

} // namespace simple_router

#endif // SIMPLE_ROUTER_ROUTING_TABLE_HPP
