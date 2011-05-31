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
    print_err("Invalid filter");
    return -1;
  }
  if(pcap_setfilter(session, &fp) == -1) {
    print_err("Failed to set filter");
    return -1;
  }
  return 1;
}
