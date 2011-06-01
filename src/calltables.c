#include "calltables.h"
#include "network.h"
#include "packet.h"
void* ip_suite[MAX_PROTOCOLS] = {0};
void setup_basic_ip_calls(void) {
  //icmp 1
  //igmp 2
  ip_suite[6] = (void*)print_tcp_pkt;
  //udp 17
  //ipv6 29
  //routing header ipv6 43
  //fragment header ipv6 44
  //
}
