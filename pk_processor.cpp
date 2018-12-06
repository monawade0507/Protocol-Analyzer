//
// Created by Phil Romig on 11/13/18.
//

#include "packetstats.h"
#include <cmath>
#include <bitset>

// ****************************************************************************
// * pk_processor()
// *  Most/all of the work done by the program will be done here (or at least it
// *  it will originate here). The function will be called once for every
// *  packet in the savefile.
// ****************************************************************************
void pk_processor(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    resultsC* results = (resultsC*)user;
    results->incrementTotalPacketCount();
    DEBUG << "Processing packet #" << results->packetCount() << ENDL;
    char s[256]; bzero(s,256); bcopy(ctime(&(pkthdr->ts.tv_sec)),s,strlen(ctime(&(pkthdr->ts.tv_sec)))-1);
    TRACE << "\tPacket timestamp is " << s;
    TRACE << "\tPacket capture length is " << pkthdr->caplen ;
    TRACE << "\tPacket physical length is " << pkthdr->len ;  // not recommended to use

    // *************************************************************************************************
    // BASIC INFORMATION
    //
    // Minimum size for char is 8 bits or 1 octet
    // Destination and Source MAC addresses are each 6 octets : 0x------
    // EtherType is 2 octets : 0x-- {
    //                         Values of 1500 and below mean that it is used to indcate size 
    //                         Values of 1536 and above indicate that it is used as an EtherType
    //                         ( this indicates which protocol is encapsulated in the payload frame )
    //                       }

    // Detecting Ethernet or IEEE 802.3
    if (pkthdr->caplen <= 1536) {
        results->newEthernet(pkthdr->caplen);

	int desLen = 6;
	int srcLen = 6;
	int typeLen = 2;

        int macHeader = 14;      // MAC Header os 14 bytes ( 14 octets )
        int IP_Len = 4;          // Both Desination and Source IP addresses are 32 bytes ( 32 octects )
        int srcIPStartBit = 26;  // Starting bit for Source IP address
        int desIPStartBit = 30; // Starting bit for Destination IP address
        int srcPortBit = 34;
        int destPortBit = 36;
        int type_val = 0; 
        int port = 0;
        unsigned int linkLayerSize = pkthdr->caplen;
        unsigned int transLayerSize = pkthdr->caplen;

        uint64_t srcMac = 0;
        uint64_t dstMac = 0;
        uint32_t srcIPv4;
        uint32_t dstIPv4;
        uint32_t srcUDP;
        uint32_t dstUDP;
        uint32_t srcTCP;
        uint32_t dstTCP;

        std::stringstream buf_mac;
	std::stringstream buf_ip;
        std::stringstream buf_port;
        std::stringstream temp;
     
        std::string dest_mac = "";
        std::string src_mac = "";
        std::string type_hex = "0x";
        std::string etherType = "";
        std::string dest_ip = "";
        std::string src_ip = "";
        std::string ipFlags = "";
        std::string protocol = "";
        std::string srcPort = "";
        std::string destPort = "";
        std::string tcpFlags = "";

        bool foundUDP = false;
        bool foundTCP = false;

	buf_mac.clear();
        buf_mac.str(std::string());

        // Read through the buff and get the Source and Destination MAC address and EtherType
	for (int i = 0 ; i < desLen; i++) {
            buf_mac << std::setfill('0') << std::hex << (int)packet[i]; 
            if (i < desLen - 1) buf_mac <<  ":" ;}
        buf_mac >> dstMac;
        dest_mac = buf_mac.str();

        // Clearing buf for re-use
        buf_mac.clear();
        buf_mac.str(std::string());
        buf_ip.clear();
        buf_ip.str(std::string());

        for (int i = 0; i < desLen; i++) {
            temp << std::setfill('0') << std::hex << (int)packet[i]; }
        temp >> dstMac;
        temp.clear();
        temp.str(std::string());

        for (int i = 0; i < srcLen; i++) {
            buf_mac << std::setfill('0') << std::hex << (int)packet[desLen + i];
            if (i < desLen - 1) buf_mac << ":" ;}
        buf_mac >> srcMac;
        src_mac = buf_mac.str();

        // Clearing buf for re-use
        buf_mac.clear();
        buf_mac.str(std::string());
        buf_ip.clear();
        buf_ip.str(std::string());

        for (int i = 0; i < srcLen; i++) {
            temp << std::setfill('0') << std::hex << (int)packet[desLen + i]; }
        temp >> srcMac;

        temp.clear();
        temp.str(std::string());

        for (int i = 0; i < typeLen; i++) {
            buf_mac << std::setfill('0') << std::setw(2) << std::hex << (int)packet[desLen + srcLen + i] ;
            buf_ip << (int)packet[desLen + srcLen + i] ;}
	type_hex += buf_mac.str();
        etherType += buf_ip.str();

        // Clearing buf for reuse
        buf_mac.clear();
        buf_mac.str(std::string());
        buf_ip.clear();
        buf_ip.str(std::string());

	// Evaluate type_hex to decimal number to determines the EtherType
	for (int i = 0; i < etherType.length(); i++) {
            temp << etherType[i];
            int val = 0;
            temp >> val;
            type_val += pow(16, etherType.length() - i) * val; }
        // Clear temp buffer for re-use
        temp.clear();
        temp.str(std::string());

	// Printing answers
        TRACE << "\tSource MAC = " << src_mac;
        TRACE << "\tDestination MAC = " << dest_mac;
        TRACE << "\tEther Type = " << type_val;

	// Determining and printing the Ether Type packet and packet size
	if (type_hex.find("0800")) { TRACE << "\tPacket is " << "IPv4" ;}
	else if (type_hex.find("08DD") || type_hex.find("08dd")) { TRACE << "\tPacket is " << "IPv6" ;}
	else { TRACE << "\t Packet is " << "OtherNetwork" ;}

        // Find the size of the link layer
	//for (int i = 0; i < 2; i++) {
        //    temp << std::setfill('0') << std::setw(2) << std::hex << (int)packet[16 + i]; }
        //temp >> linkLayerSize;
	//temp.clear();
        //temp.str(std::string());

	if (type_hex.find("0800")) { results->newIPv4(linkLayerSize); }
        else if (type_hex.find("08DD")) { results->newIPv6(linkLayerSize); }
        else { results->newOtherNetwork(linkLayerSize); }

	// Reading through the packet and determining the Source and Destination IP
        for (int i = 0; i < IP_Len; i++) {
            buf_ip << (int)packet[srcIPStartBit + i];
            if (i < IP_Len - 1) buf_ip << "." ;}
        buf_ip >> srcIPv4;
        src_ip = buf_ip.str();
	// Clear the buf for re-use
        buf_ip.clear();
        buf_ip.str(std::string());

        for (int i = 0; i < IP_Len; i++) {
            buf_ip << (int)packet[desIPStartBit + i];
            if (i < IP_Len - 1) buf_ip << ".";}
        buf_ip >> dstIPv4;
        dest_ip = buf_ip.str();
        // Clear the buf for re-use
        buf_ip.clear();
        buf_ip.str(std::string());

        // Printing answers
        TRACE << "\tSource IP Address = " << src_ip;
        TRACE << "\tDestination IP Address = " << dest_ip;

        /************************************************
        List of IP protocol numbers
        UDP = 0x11 or 17
        TCP = 0x06 or 6
        IPv6-ICMP = 0x3A
        *////////////////////////////////////////////////
        //for (int i = 0; i < 2; i++) {
        //    temp << std::setfill('0') << std::setw(2) << std::hex << (int)packet[38 + i]; }
	//temp >> transLayerSize;
        //temp.clear();
        //temp.str(std::string());        

   
        // Detecting the Protocol Field
	temp << std::setfill('0') << std::setw(2) << std::hex << (int)packet[23];
        if (temp.str() == "06") { protocol = "TCP"; foundTCP = true; results->newTCP(transLayerSize);}
        else if (temp.str() == "11") { protocol = "UDP"; foundUDP = true; results->newUDP(transLayerSize);}
        else if (temp.str() == "3A") { protocol = "ICMP"; results->newICMP(transLayerSize);}
        else { protocol = "OtherTransport"; results->newOtherTransport(transLayerSize);} 
        temp.clear();
        temp.str(std::string());

	// Printing answers
        TRACE << "\tPacket is " << protocol;        

        // Reading through the packet and determining the Source and Destination Port
        for (int i = 0; i < 2; i++) {
            buf_port << std::setfill('0') << std::setw(2) << std::hex << (int)packet[srcPortBit + i]; }
        
        char hexStrSrc[10];
        buf_port >> hexStrSrc;
        int num = (int)strtol(hexStrSrc, NULL, 16);
        srcPort = std::to_string(num);

        if (foundUDP) { temp << srcPort; temp >> srcUDP; }
        temp.clear();
        temp.str(std::string());
        if (foundTCP) { temp << srcPort; temp >> srcTCP; }
        temp.clear();
        temp.str(std::string());

        buf_port.clear();
        buf_port.str(std::string()); 
	
        for (int i = 0; i < 2; i++) {
            buf_port << std::setfill('0') << std::setw(2) << std::hex << (int)packet[destPortBit + i]; }
          
        char hexStrDest[10];
        buf_port >> hexStrDest;
        num = (int)strtol(hexStrDest, NULL,16);
        destPort = std::to_string(num);

        if (foundUDP) { temp << destPort; temp >> dstUDP; }
        temp.clear();
	temp.str(std::string());
        if (foundTCP) { temp << destPort; temp >> dstTCP; }
	temp.clear();
        temp.str(std::string()); 

	// Cleangin buf for re-use
        buf_port.clear();
        buf_port.str(std::string());

        // Printing answers
        TRACE << "\tSource Port #" << srcPort;
        TRACE << "\tDestination Port #" << destPort;

	// Filling in results with required values
        results->newSrcMac(srcMac);
        results->newDstMac(dstMac);
        results->newSrcIPv4(srcIPv4);
        results->newDstIPv4(dstIPv4);
        if (foundUDP) { results->newSrcUDP(srcUDP); results->newDstUDP(dstUDP); }
        if (foundTCP) { results->newSrcTCP(srcTCP); results->newDstTCP(dstTCP); }

        
	buf_port << packet[47];
	uint8_t flagNum;
        buf_port >> flagNum;
        tcpFlags = std::bitset<8>(flagNum).to_string();
        // testing FIN flag
        if (foundTCP) {if (tcpFlags[7] == '1') { results->incrementFinCount(); TRACE << "\tFIN bit set";}}
        // testing Sun flag
        if (foundTCP) {if (tcpFlags[6] == '1') { results->incrementSynCount(); TRACE << "\tSYN bit set";}}

        // Cleaning buf for re-use
        buf_port.clear();
        buf_port.str(std::string());

	// Fragment Offset flag
         buf_port << packet[54];
         uint8_t fragment;
         buf_port >> fragment;
         tcpFlags = std::bitset<8>(fragment).to_string();
         
         if (foundTCP) {if (tcpFlags[0] == '1') { results->incrementFragCount(); TRACE << "\tMore-Fragments bit set";}}
            

    }
    else {
        results->newIEEE(pkthdr->caplen);

    }

    return;
}
