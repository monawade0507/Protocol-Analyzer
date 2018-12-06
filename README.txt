# Protocol-Analyzer
will use the pcap library to write a Protocol Analyzer, giving you an opportunity to review three of the four layers of the network.

Student name: Demonna Wade

I tested my code with sample.pcp.

I used the skeleton code.  
For printing information to console, I used the TRACE level of logging. 

The code implemented in the file pk_processor.cpp.
I computed all of the information listed in the assignment:
- Largest, smallest, and average packet size of each type
- I handled the following layers: Link layer, Network layer, Transport Layer
- I reported the source and destination MAC and IPv4 addresses and UDP and TCP port numbers.
- I was also able to get the TCP-SYN bit, TCP-FIN bit, and TCP-More-Fragments bit.

I matched the output of the sample.pcp file produced using the professor's executable. 

I did use the resultsC class to report the accumulate statistics. 


