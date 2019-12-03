#include <iostream>

#include "routing-table.hpp"
#include "core/utils.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

namespace simple_router {

RoutingTableEntry
RoutingTable::lookup(uint32_t ip) const
{
  u_int8_t longest_mask = 0;
  RoutingTableEntry res;
  bool found = false;

  std::cerr << "\tLooping through all Routing Table Entries: " << std::endl;
  for (auto entry : m_entries) {
    std::cerr << "\t" << entry.ifName << ": ";
    std::cerr << "\n\t\tip: " << ipToString(entry.gw);
    std::cerr << "\n\t\tgate: " << ipToString(entry.gw);
    std::cerr << "\n\t\tmask: " << ipToString(entry.mask) << std::endl;
    uint32_t prefix_mask = entry.mask;
    if ((prefix_mask & entry.gw) == (prefix_mask & ip) && entry.mask >= longest_mask) {
      longest_mask = entry.mask;
      res = entry;
      found = true;
    }
  }

  std::cerr << "Done. \nEntry with longest matching prefix: ";
  std::cerr << res.ifName << std::endl;

  if (found) {
    return res;
  }
  throw std::runtime_error("Routing entry not found");
}

bool
RoutingTable::load(const std::string& file)
{
  FILE* fp;
  char  line[BUFSIZ];
  char  dest[32];
  char  gw[32];
  char  mask[32];
  char  iface[32];
  struct in_addr dest_addr;
  struct in_addr gw_addr;
  struct in_addr mask_addr;

  if (access(file.c_str(), R_OK) != 0) {
    perror("access");
    return false;
  }

  fp = fopen(file.c_str(), "r");

  while (fgets(line, BUFSIZ, fp) != 0) {
    sscanf(line,"%s %s %s %s", dest, gw, mask, iface);
    if (inet_aton(dest, &dest_addr) == 0) {
      fprintf(stderr,
              "Error loading routing table, cannot convert %s to valid IP\n",
              dest);
      return false;
    }
    if (inet_aton(gw, &gw_addr) == 0) {
      fprintf(stderr,
              "Error loading routing table, cannot convert %s to valid IP\n",
              gw);
      return false;
    }
    if (inet_aton(mask, &mask_addr) == 0) {
      fprintf(stderr,
              "Error loading routing table, cannot convert %s to valid IP\n",
              mask);
      return false;
    }

    addEntry({dest_addr.s_addr, gw_addr.s_addr, mask_addr.s_addr, iface});
  }
  return true;
}

void
RoutingTable::addEntry(RoutingTableEntry entry)
{
  m_entries.push_back(std::move(entry));
}

std::ostream&
operator<<(std::ostream& os, const RoutingTableEntry& entry)
{
  os << ipToString(entry.dest) << "\t\t"
     << ipToString(entry.gw) << "\t"
     << ipToString(entry.mask) << "\t"
     << entry.ifName;
  return os;
}

std::ostream&
operator<<(std::ostream& os, const RoutingTable& table)
{
  os << "Destination\tGateway\t\tMask\tIface\n";
  for (const auto& entry : table.m_entries) {
    os << entry << "\n";
  }
  return os;
}

} // namespace simple_router
