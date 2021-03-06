#include <ctype.h>
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
    exit(FILTER_ERR);
  }
  if(pcap_setfilter(session, &fp) == -1) {
    print_err("Failed to set filter");
    exit(FILTER_ERR);
  }
  return 1;
}

void handle_pcap_pkt(u_char* args, const struct pcap_pkthdr* header,
                     const u_char* packet) {
  const struct ethernet_hdr* eth_header;
  const struct ip_hdr* ip_header;
  
  u_int ip_hdr_sz;

  eth_header = (struct ethernet_hdr*)(packet);
  ip_header = (struct ip_hdr*)(packet + SIZE_ETHERNET);
  ip_hdr_sz = IP_HDRLEN(ip_header)*4;
  if (ip_hdr_sz < 20) {
    return;
  }
  print_pkt(eth_header, ip_header, ip_hdr_sz, ((void*)packet+SIZE_ETHERNET+ip_hdr_sz));
}

void print_pkt(const struct ethernet_hdr* eth, const struct ip_hdr* ip,
               u_int ip_hdr_sz, const void* packet) {
  printf("*********************CAPTURED PACKET*************************\n");
  printf("********************ETHERNET HEADER DATA*************************\n");
  printf("SRC ADDRESS: %02x:%02x:%02x:%02x:%02x:%02x\n",
         eth->src_addr[0], eth->src_addr[1],
         eth->src_addr[2], eth->src_addr[3],
         eth->src_addr[4], eth->src_addr[5]);
  printf("DEST ADDRESS: %02x:%02x:%02x:%02x:%02x:%02x\n",
         eth->dest_addr[0], eth->dest_addr[1],
         eth->dest_addr[2], eth->dest_addr[3],
         eth->dest_addr[4], eth->dest_addr[5]);
  printf("PROTOCOL TYPE: Internet Protocol\n");
  printf("*********************IP HEADER DATA****************************\n");
  printf("VERSION: %02d\n", IP_VERSION(ip));
  printf("TYPE OF SERVICE: %d\n", ip->tos);
  printf("TOTAL LENGTH: %d\n", ip->len);
  printf("IDENTIFICATION: %d\n", ip->id);
  printf("REMAINING TTL: %d\n", ip->ttl);
  printf("SOURCE ADDRESS: %s\n", inet_ntoa(ip->src_ip));
  printf("DEST ADDRESS: %s\n", inet_ntoa(ip->dest_ip));
  switch(ip->prot) {
  case TCP_PACKET:
    {
      u_int tcp_hdr_sz;
      char* pkt_data;
      const struct tcp_hdr* tcp = (struct tcp_hdr*)(packet +
                                                    SIZE_ETHERNET + ip_hdr_sz);
      tcp_hdr_sz = TCP_OFFSET(tcp)*4;
      if (tcp_hdr_sz < 20) {
        return;
      }
      pkt_data = (char*)(packet + SIZE_ETHERNET + ip_hdr_sz + tcp_hdr_sz);
      printf("*********************TCP HEADER DATA***************************\n");
      printf("SOURCE PORT: %d\n", tcp->src_prt);
      printf("DEST PORT: %d\n", tcp->dest_prt);
      printf("SEQUENCE #: %d\n", ntohl(tcp->seq));
      printf("ACK #: %d\n", ntohl(tcp->ack));
      printf("OFFSET: %d\n", TCP_OFFSET(tcp));
      printf("FLAGS: %d\n", tcp->flags);
      printf("WINDOW POSITION: %d\n",tcp->win);
      if(ip->len - tcp_hdr_sz - ip_hdr_sz > 0) {
        printf("*******************PACKET_PAYLOAD DATA*************************\n");
        printf("%s\n", pkt_data);
      }
    }
    break;
  case UDP_PACKET:
    {
      const struct udp_hdr* udp_header = 
        (struct udp_hdr*)(packet + SIZE_ETHERNET + ip_hdr_sz);
      char* pkt_data = (char*)(packet + SIZE_ETHERNET + ip_hdr_sz + SIZE_UDP);
      printf("*********************UDP HEADER DATA***************************\n");
      printf("SOURCE PORT: %d\n", udp_header->src_prt);
      printf("DEST PORT: %d\n", udp_header->dest_prt);
      if(ip->len - SIZE_UDP - ip_hdr_sz > 0) {
        printf("*******************PACKET_PAYLOAD DATA*************************\n");
        printf("%s\n", pkt_data);
      }
    }
    break;
  default:
    printf("Unsupported Packet Type.\n");
    break;
  }
  printf("\n\n");
}
void format_data(char* data, u_short len) {
  register unsigned short i;
  for(i = 0; i < len; ++i) {
    if(!isprint(data[i])) {
      data[i] = '.';
    }
  }
}
