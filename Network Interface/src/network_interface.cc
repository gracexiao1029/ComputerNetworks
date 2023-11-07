#include "network_interface.hh"

#include "arp_message.hh"
#include "ethernet_frame.hh"

using namespace std;

// ethernet_address: Ethernet (what ARP calls "hardware") address of the interface
// ip_address: IP (what ARP calls "protocol") address of the interface
NetworkInterface::NetworkInterface( const EthernetAddress& ethernet_address, const Address& ip_address )
  : ethernet_address_( ethernet_address ), ip_address_( ip_address )
{
  cerr << "DEBUG: Network interface has Ethernet address " << to_string( ethernet_address_ ) << " and IP address "
       << ip_address.ip() << "\n";
}

// dgram: the IPv4 datagram to be sent
// next_hop: the IP address of the interface to send it to (typically a router or default gateway, but
// may also be another host if directly connected to the same network as the destination)

// Note: the Address type can be converted to a uint32_t (raw 32-bit IP address) by using the
// Address::ipv4_numeric() method.
void NetworkInterface::send_datagram( const InternetDatagram& dgram, const Address& next_hop )
{
  EthernetFrame frame;
  const uint32_t ip_next_hop_32b = next_hop.ipv4_numeric();
  const uint32_t ip_addr_32b = ip_address_.ipv4_numeric();
  
  // MAC address of next hop IP is found
  if (arp_table_.contains(ip_next_hop_32b)) {
    EthernetHeader frame_header;
    frame_header.dst = arp_table_[ip_next_hop_32b].second;
    frame_header.src = ethernet_address_;
    frame_header.type = EthernetHeader::TYPE_IPv4;
    
    // send serialized datagram
    frame.header = frame_header;
    frame.payload = serialize(dgram);
  } else { // MAC address of next hop IP is not found
    // ARP request sent for the same IP in the last 5000 ms
    if (queue_table_.contains(ip_next_hop_32b)) {
      queue_table_[ip_next_hop_32b].second.push(dgram);
      return;
    }
    // broadcast an ARP request to find MAC address
    ARPMessage arpmsg;
    arpmsg.opcode = ARPMessage::OPCODE_REQUEST;
    arpmsg.sender_ethernet_address = ethernet_address_;
    arpmsg.sender_ip_address = ip_addr_32b;
    arpmsg.target_ethernet_address = EthernetAddress{0};
    arpmsg.target_ip_address = ip_next_hop_32b;

    EthernetHeader frame_header;
    frame_header.dst = EthernetAddress{ETHERNET_BROADCAST};
    frame_header.src = ethernet_address_;
    frame_header.type = EthernetHeader::TYPE_ARP;

    // send serialized ARP message
    frame.header = frame_header;
    frame.payload = serialize(arpmsg);

    // append the packet to queue and wait for response
    queue_table_[ip_next_hop_32b].first = curr_time_;
    queue_table_[ip_next_hop_32b].second.push(dgram);
  }
  // push the ready frame to frame queue
  frame_queue_.push(frame);
}

// frame: the incoming Ethernet frame
// receive a frame, check whether we use or discard it
optional<InternetDatagram> NetworkInterface::recv_frame( const EthernetFrame& frame )
{
  const EthernetAddress packet_dst = frame.header.dst;
  const uint16_t packet_type = frame.header.type;
  const uint32_t ip_addr_32b = ip_address_.ipv4_numeric();

  // the packet is destined for this machine
  if (packet_dst == ethernet_address_ || packet_dst == ETHERNET_BROADCAST) {
    if (packet_type == EthernetHeader::TYPE_IPv4) {
      // parse the payload as an InternetDatagram
      InternetDatagram dgram;
      if (parse(dgram, frame.payload)) {
        return dgram;
      }
    } else if (packet_type == EthernetHeader::TYPE_ARP) {
      // process ARP packet
      // parse the payload as an ARPMessage
      ARPMessage arpmsg;
      if (parse(arpmsg, frame.payload)) {
        // add to ARP cache table
        arp_table_[arpmsg.sender_ip_address] = make_pair(curr_time_, arpmsg.sender_ethernet_address);
        
        // ARP requests IP address
        if (arpmsg.opcode == ARPMessage::OPCODE_REQUEST && arpmsg.target_ip_address == ip_addr_32b) {
          arpmsg.opcode = ARPMessage::OPCODE_REPLY;
          arpmsg.target_ethernet_address = arpmsg.sender_ethernet_address;
          arpmsg.target_ip_address = arpmsg.sender_ip_address;
          arpmsg.sender_ethernet_address = ethernet_address_;
          arpmsg.sender_ip_address = ip_addr_32b;
          
          EthernetHeader frame_header;
          frame_header.dst = arpmsg.target_ethernet_address;
          frame_header.src = ethernet_address_;
          frame_header.type = EthernetHeader::TYPE_ARP;
          
          EthernetFrame result_frame;
          result_frame.header = frame_header;
          result_frame.payload = serialize(arpmsg);
          
          frame_queue_.push(result_frame);
        }

        // send all waiting datagram in queue
        while (!queue_table_[arpmsg.sender_ip_address].second.empty()) {
          EthernetHeader reply_frame_header;
          reply_frame_header.dst = arpmsg.sender_ethernet_address;
          reply_frame_header.src = ethernet_address_;
          reply_frame_header.type = EthernetHeader::TYPE_IPv4;
          EthernetFrame reply_frame;
          // send serialized datagram
          reply_frame.header = reply_frame_header;
          reply_frame.payload = serialize(queue_table_[arpmsg.sender_ip_address].second.front());
          frame_queue_.push(reply_frame);
          queue_table_[arpmsg.sender_ip_address].second.pop();
        }
      }
    }
  }
  // discard the packet
  return {};
}

// ms_since_last_tick: the number of milliseconds since the last call to this method
// call tick function periodically.
void NetworkInterface::tick( const size_t ms_since_last_tick )
{
  // update current time
  curr_time_ += ms_since_last_tick;
  // erase all expired address in arp cache table
  erase_expired_item(arp_table_, 30000);
  // erase all expired ARP request in queue table
  erase_expired_item(queue_table_, 5000);
}

optional<EthernetFrame> NetworkInterface::maybe_send()
{
  // No packet ready in the queue
  if (frame_queue_.empty()) {
    return {};
  }
  // Pop and return the oldest ready-to-be-sent packet
  EthernetFrame oldest_packet = frame_queue_.front();
  frame_queue_.pop();
  return oldest_packet;
}

void NetworkInterface::erase_expired_item(auto& map, size_t expire_time) {
  size_t time_diff;
  std::vector<uint32_t> discard_ip;
  for (auto ip : map) {
    // time difference between the current time and the IP creating time
    time_diff = curr_time_ - map[ip.first].first;
    if (time_diff > expire_time) {
      discard_ip.emplace_back(ip.first);
    }
  }

  // erase all unavailable IP
  for (auto ip : discard_ip) {
    map.erase(ip);
  }
}