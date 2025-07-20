# Router Dataplane Implementation

## Description:
This project showcases a complete implementation of a software-based IPv4 router dataplane, developed in C. The router is capable of dynamically routing packets
using a static or dynamically populated ARP table, handling various ICMP scenarios, and efficiently computing the best forwarding route using a Longest Prefix Match (LPM) structure.

## Usage:
### Automatically:
Make sure you are in the router-dataplane directory before running the script.
To run the automatic tests, use the checker.py script by executing:
`./checker/checker.py`

### Manual Testing:
Each host is a simple Linux machine. From its terminal, you can run commands that generate IP traffic to test the functionality of the implemented router.
I recommend using tools such as arping, ping, and netcat. Additionally, you can inspect packets using wireshark or tcpdump from the terminal.

Use the following command to open the topology:
`sudo python3 ./checker/topo.py`

To compile the code, use the `make` command, which will build the router binary.
To start the routers manually, use the following commands -> the first one from router0's terminal, and the second from router1's terminal:

`make run_router0`    # run from router0's terminal
`make run_router1`    # run from router1's terminal

To avoid typing the full IP address of a host, you can use h0, h1, h2, and h3 as aliases (e.g., ping h1).


## Features Implemented
### Dynamic ARP Table Management
- Sends and processes ARP requests and replies.
- Builds and updates a dynamic ARP cache (IP <–> MAC mapping).
- Queues packets for unresolved MAC addresses and forwards them once resolved.

### IPv4 Packet Forwarding
- Implements routing decisions using a static routing table.
- Handles TTL decrement, checksum recomputation and Ethernet frame rewriting.
- Sends ICMP "Destination Unreachable" messages when no valid route is found.

### Efficient Longest Prefix Match (LPM)
- Built a custom binary trie structure for prefix matching.
- Achieves O(32) lookup time for the best route match.
- Each node stores prefix-specific routing information for efficient backtracking.

### ICMP Handling -> Correctly processes and replies to:
- ICMP Echo Requests (type 8) with Echo Replies (type 0).
- ICMP Time Exceeded (TTL expired).
- ICMP Destination Unreachable.
- Extracts ID and SEQ fields from the incoming packet for correct Echo Reply behavior.

## Design and Implementation Highlights
- Modular packet parsing, header manipulation using C structs.(arp_hdr, ether_hdr, ip_hdr, icmp_hdr) and careful handling of memory when
constructing ARP and ICMP packets.
- I have a clear separation between forwarding logic, ARP management, and ICMP generation.
- I fixed subtile bugs (ex: forgetting to zero out the checksum before recomputation, or not storing the full original packet in ARP queues).
- ARP packet construction achieved via memory block splitting and casting, like in the example below:

`uint8_t pachet_arp[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)];`
`struct ether_hdr *parte_eth = (struct ether_hdr *)pachet_arp;`
`struct arp_hdr *parte_arp = (struct arp_hdr *)(pachet_arp+ sizeof(struct ether_hdr));`

## Dynamic ARP Cache Population
When the router receives an IPv4 packet (i.e., the Ethernet header has type 0x0800), the first step is to check the ARP table (a vector of IP–MAC struct associations) to see if the destination IP address of the packet is already associated with a known hardware (MAC) address.
There are two scenarios:
	1. If the MAC address is known, the packet is forwarded directly on the interface corresponding to the best route.
	2. If the MAC address is unknown, an ARP request is broadcasted to all devices on the router’s network. The ARP header fields are populated according to both the requirements and examples found online (e.g: YouTube tutorials). Meanwhile, the original IPv4 packet is placed in a queue.
Once a reply is received, packets are dequeued and two cases may occur:
	1. If the MAC address has been successfully resolved, the packet is immediately forwarded.
	2. If it still isn’t present in the ARP cache, the packet is re-queued to wait for a valid mapping. So it keeps waiting...

## ICMP Packet Handling
I created a separate function to generate ICMP packets with customizable parameters: mtype, mcode, num_bits (number of bits to copy from the original packet), the interface to send the ICMP packet back through (this is the same interface the faulty or expired packet arrived on), id and seq fields (important for ICMP Echo Reply to correctly reflect the original Echo Request values)
### This function builds the ICMP packet by concatenating:
Ethernet header + IPv4 header + ICMP segment (which itself includes a new IP header and some data bits)
### Observation:
It took me quite a while to realize why the last two tests kept failing — both when run manually and via the checker.
Initially, I was sending an ICMP Echo Reply only if:
- The IP header's proto field was set to 1 (ICMP),
- The ICMP header’s type was 8 (Echo Request) and the code was 0.
However, after carefully rereading the statement, I realized I was missing an important condition: the destination IP in the IPv4 header must match the router’s own IP. Once I added this extra check, everything worked!
## Longest Prefix Match (LPM)
To make route lookup more efficient, I implemented a binary trie to perform LPM (Longest Prefix Match). Each node has: two children (left for 0, right for 1), a depth level and a routing table entry associated with the prefix represented by that node.
### How I Built It:
For each prefix in the routing table, I inserted it into the trie. If a child node for a specific bit didn’t exist, I allocated a new one with the corresponding info. Otherwise, I just traversed downward to the next node representing that bit.
