# Protocol-Analyzer
will use the pcap library to write a Protocol Analyzer, giving you an opportunity to review three of the four layers of the network.


Protocols you must recognize are:
  Link layer: Ethernet, IEE 802.3
  Network layer: IPv4, IPv6, Other-Network-Layer
  Transport Layer: TCP, UDP, ICMP, Other-Transport-Layer
  
This is the structure definition for pcap_pkthdr:

  struct pcap_pkthdr {
  
		struct timeval ts; /* time stamp */
		
		bpf_u_int32 caplen; /* length of portion present */
		
		bpf_u_int32 len; /* length this packet (off wire) */
		
	};
	
	
Helpful Link: https://www.tcpdump.org/pcap.html
