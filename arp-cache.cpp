#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

void
ArpCache::handle_arpreq(const std::shared_ptr<ArpRequest>& arp_req) {
  if (arp_req->nTimesSent >= 5) {
    // Removes the request from the queue and frees all memory (packets) associated with it
    removeRequest(arp_req);
  }
  else {
    // Build request ARP packet from scratch
    auto req_len = (sizeof(ethernet_hdr) + sizeof(arp_hdr))/sizeof(unsigned char);
    Buffer request(req_len);
    // We work on wres, because it is easier to work w/ an array, then move it into res
    uint8_t w_request[req_len];

    // Format the ethernet header of the response
    ethernet_hdr *request_eth_hdr = (ethernet_hdr *) w_request;
    // Send from interface that is sending the actual packet (all packets queued ahve the same interface)
    const Interface *arp_req_iface = m_router.findIfaceByName(((arp_req->packets).front()).iface);
    memcpy(request_eth_hdr->ether_shost, arp_req_iface->addr.data(), ETHER_ADDR_LEN);
    // Send back to the host
    memset(request_eth_hdr->ether_dhost, 0xFFFFFFFFFFFF, ETHER_ADDR_LEN);
    request_eth_hdr->ether_type = htons(ethertype_arp);

    // Format the ARP header of the response
    arp_hdr *request_arp_hdr = (arp_hdr *) (w_request + sizeof(ethernet_hdr));
    request_arp_hdr->arp_hrd = htons(arp_hrd_ethernet);
    request_arp_hdr->arp_pro = htons(ethertype_ip);
    request_arp_hdr->arp_hln = ETHER_ADDR_LEN;
    // There are 4 ensuing addresses
    request_arp_hdr->arp_pln = 4;
    request_arp_hdr->arp_op = htons(arp_op_request);
    memcpy(request_arp_hdr->arp_sha, arp_req_iface->addr.data(), ETHER_ADDR_LEN);
    request_arp_hdr->arp_sip = arp_req_iface->ip;
    memset(request_arp_hdr->arp_tha, 0xFFFFFFFFFFFF, ETHER_ADDR_LEN);
    request_arp_hdr->arp_tip = arp_req->ip;

    // Move array into Buffer
    memcpy(&request[0], &w_request[0], req_len);

    std::cerr << "----------------------------- Sending ARP request! Start of headers: " << std::endl;
    print_hdrs(request);
    std::cerr << "----------------------------- Sent ARP request! End of headers. " << std::endl << std::endl;

    m_router.sendPacket(request, arp_req_iface->name);

    // Increment nTimesSent by 1
    arp_req->timeSent = steady_clock::now();
    (arp_req->nTimesSent)++;
  }
}

void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  // Handle each requeset
  for (std::shared_ptr<ArpRequest> entry : m_arpRequests) {
    handle_arpreq(entry);
  }
  // Record entries to delete
  std::vector<std::shared_ptr<ArpEntry>> to_be_removed;
  for (std::shared_ptr<ArpEntry> entry : m_cacheEntries) {
    if (entry->isValid == false) {
      to_be_removed.push_back(entry);
    }
  }
  // Delete recorded entries
  for (std::shared_ptr<ArpEntry> entry : to_be_removed) {
    m_cacheEntries.remove(entry);
  }
}

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
          std::cerr << ipToString(entry->ip) << std::endl;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
