#include "network.h"
void get_pcap_netmask(char* device, bpf_u_int32* net, bpf_u_int32* mask) {
  char err[PCAP_ERRBUF_SIZE];
  if (pcap_lookupnet(device, net, mask, err) == -1) {
    print_err("Can't get netmask for device");
    *net = 0;
    *mask = 0;
  }
}
/**
 * Selects the pcap device to capture on.
 *
 * @author Duncan Donaldson
 * @return The device name to capture on.
 */
char* select_pcap_dev(void) {
  char err[PCAP_ERRBUF_SIZE];
  return pcap_lookupdev(err);
}
/**
 * Opens a pcap session for capturing.
 *
 *@author Duncan Donaldson
 *@param dev, The device name to capture on.
 *@return a handle to the pcap session.
 */
pcap_t* open_pcap_session(char* dev) {
  char err[PCAP_ERRBUF_SIZE];
  pcap_t* session = 0;
  if((session = pcap_open_live(dev, BUFSIZ, PROMISC_YES, STD_TIMEOUT, err)) == NULL) {
    print_pcap_err("Failed to open session:", err);
    return NULL;
  }
  return session;
}

int set_pcap_filter(pcap_t* session, char* regexp, bpf_u_int32 net) {
  struct bpf_program fp;
  if(regexp == 0) {
    return -1;
  }
  if(pcap_compile(session, &fp, regexp,
		  PCAP_COMP_NOOPTIMIZE, net) == -1) {
    print_pcap_err("Invalid filter:", regexp);
    return -1;
  }
  if(pcap_setfilter(session, &fp) == -1) {
    print_err("Failed to set filter");
    return -1;
  }
  return 1;
}

void handle_pcap_pkt(u_char* args, const struct pcap_pkthdr* header,
		     const u_char* packet) {
  const struct ethernet_hdr* eth_header;
  const struct ip_hdr* ip_header;
  const struct tcp_hdr* tcp_header;
  const char* pkt_data;
  
  u_int ip_hdr_sz;
  u_int tcp_hdr_sz;

  eth_header = (struct ethernet_hdr*)(packet);
  ip_header = (struct ip_hdr*)(packet + SIZE_ETHERNET);
  ip_hdr_sz = IP_HL(ip_header)*4;
  if (ip_hdr_sz < 20) {
    print_err("Invalid IP header length\n");
    return;
  }
  tcp_header = (struct tcp_hdr*)(packet + SIZE_ETHERNET + ip_hdr_sz);
  tcp_hdr_sz = TH_OFF(tcp_header)*4;
  if (tcp_hdr_sz < 20) {
    print_err("Invalid TCP header length\n");
    return;
  }
  pkt_data = (char *)(packet + SIZE_ETHERNET + ip_hdr_sz + tcp_hdr_sz);
  print_tcp_pkt(eth_header, ip_header, tcp_header, pkt_data);
}
void print_tcp_pkt(const struct ethernet_hdr* eth, const struct ip_hdr* ip,
		   const struct tcp_hdr* tcp, const char* data) {
  printf("*********************CAPTURED PACKET*************************\n");
  printf("******************ETHERNET HEADER DATA***********************\n");
  printf("SRC ADDRESS: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
	 eth->src_addr[0] >> 4, eth->src_addr[0] & 0x0f,
	 eth->src_addr[1] >> 4, eth->src_addr[1] & 0x0f,
	 eth->src_addr[2] >> 4, eth->src_addr[2] & 0x0f,
	 eth->src_addr[3] >> 4, eth->src_addr[3] & 0x0f,
	 eth->src_addr[4] >> 4, eth->src_addr[4] & 0x0f,
	 eth->src_addr[5] >> 4, eth->src_addr[5] & 0x0f);
  printf("DEST ADDRESS: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
	 eth->dest_addr[0] >> 4, eth->dest_addr[0] & 0x0f,
	 eth->dest_addr[1] >> 4, eth->dest_addr[1] & 0x0f,
	 eth->dest_addr[2] >> 4, eth->dest_addr[2] & 0x0f,
	 eth->dest_addr[3] >> 4, eth->dest_addr[3] & 0x0f,
	 eth->dest_addr[4] >> 4, eth->dest_addr[4] & 0x0f,
	 eth->dest_addr[5] >> 4, eth->dest_addr[5] & 0x0f);
}
