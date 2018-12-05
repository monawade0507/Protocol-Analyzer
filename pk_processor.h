//
// Created by Phil Romig on 10/30/18.
//

#ifndef PACKETSTATS_PK_PROCESSOR_H
#define PACKETSTATS_PK_PROCESSOR_H

// Prototype for the packet processor, called once for each packet.
void pk_processor(u_char *, const struct pcap_pkthdr *, const u_char *);

#endif // PACKETSTATS_PK_PROCESSOR_H
