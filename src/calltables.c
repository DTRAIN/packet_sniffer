#include "calltables.h"
#include "network.h"
#include "packet.h"
void* ip_protocol[MAX_PROTOCOLS];
void setup_basic_ip_calls() {
  //icmp 1
  //igmp 2
  ip_protocol+6 = (void*)print_tcp_packet;
  //udp 17
  //ipv6 29
  //routing header ipv6 43
  //fragment header ipv6 44
  //
}
