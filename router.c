#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#define IP_HDR_LEN sizeof(struct ip_hdr)
#define ETHER_HDR_LEN sizeof(struct ether_hdr)
#define ARP_HDR_LEN sizeof(struct arp_hdr)
#define ICMP_HDR_LEN sizeof(struct icmp_hdr)

struct route_table_entry *routing_table;
int routing_table_size;
struct arp_table_entry *arp_table;
int arp_table_size;
struct queue *packets_queue;

struct queue_packet
{
	// next hop, si I know to which destination IP address this packet should be sent.
	uint32_t next_hop;
	// the interface on which the packet should be sent.
	size_t interface;
	// as well as the MAC address of the current interface.
	uint8_t mac[6];
	// all the data from the packet.
	uint8_t *buf;
	// the actual length of the original IPv4 packet.
	size_t len;
};

typedef struct node
{
	struct node *children[2];
	// I can have maximum 2 children, as the tree will be a binary one.
	uint32_t next_hop;
	struct route_table_entry *route;
	int depth;
	// the depth of the node in the tree.
	int info;
	// 0 or 1.
} Node, *Tree;

Tree NodeAllocation(int info)
{
	Tree node = malloc(sizeof(Node));
	if (!node)
	{
		return NULL;
	}
	node->children[0] = NULL;
	node->children[1] = NULL;
	node->depth = 0;
	node->info = info;
	node->route = NULL;
	return node;
}
int *ip_to_binary_array(uint32_t ip)
{
	int *binary_array = malloc(sizeof(int) * 32);
	// Create an array of bits, each element being the result
	// of the AND operation between ip and 1. (And shift
	// the ip to the right, analyzing each bit one by one)
	for (int i = 0; i < 32; i++)
	{
		binary_array[i] = (ip >> (31 - i)) & 1;
	}
	return binary_array;
}

int calculate_prefix_length(uint32_t mask)
{
	int count = 0;
	for (int i = 0; i < 32; i++)
	{
		// Check one by one if the current bit is set.
		// Shift right to look at the current bit.
		if (mask & (1 << (31 - i)))
		{
			count++;
		}
		else
		{
			break;
		}
	}
	return count;
}
void TreeInsertion(Tree tree, struct route_table_entry *entry)
{
	Tree node = tree;
	int *binary_array = ip_to_binary_array(ntohl(entry->prefix));
	int prefix_length = calculate_prefix_length(ntohl(entry->mask));
	// I take each bit from the IP address and either allocate a node if it hasn't been allocated,
	// or move to that node, and so on until I reach the leaves.
	for (int i = 0; i < prefix_length; i++)
	{
		if (binary_array[i] == 0)
		{
			if (node->children[0] == NULL)
			{
				node->children[0] = NodeAllocation(0);
				node->children[0]->depth = node->depth + 1;
			}
			node = node->children[0]; // if the node with bit 0 is already allocated, just move to its branch.
		}
		else
		{
			if (node->children[1] == NULL)
			{
				node->children[1] = NodeAllocation(1);
				node->children[1]->depth = node->depth + 1;
			}
			node = node->children[1];
		}
	}
	node->route = entry;
}

void insert_all(Tree tree, struct route_table_entry *routing_table, int size)
{
	for (int i = 0; i < size; i++)
	{
		TreeInsertion(tree, &routing_table[i]);
	}
}
// void printTree(Tree tree) {
// 	if (tree == NULL) {
// 		return;
// 	}
// 	printf("current node with info: %d on depth: %d\n", tree->info, tree->depth);
// 	printTree(tree->children[0]);
// 	printTree(tree->children[1]);
// }

struct route_table_entry *find_longest_prefix_match(Tree tree, uint32_t ip_dest)
{
	int *binary_array = ip_to_binary_array(ntohl(ip_dest));
	struct route_table_entry *matched_entry = NULL;
	int max_depth = -1;

	Tree node = tree;
	// Iterate through the bits of the destination IP address.
	// Depending on the bit value, traverse the left or right branch,
	// keeping track of the routing table entry for each node (possible longest prefix match).
	// At the end, return the matched_entry.
	for (int i = 0; i < 32; i++)
	{
		// If there are no more children, we've reached a leaf node.
		// Stop and return what we've found so far, if anything.
		if (node->children[binary_array[i]] == NULL)
		{
			break;
		}
		// Move to the left or right branch.
		if (binary_array[i] == 0)
		{
			node = node->children[0];
		}
		else
		{
			node = node->children[1];
		}
		// At each node, if there is a routing entry and its depth is greater than the current max,
		// update the matched_entry and max_depth.
		if (node->route != NULL && node->depth > max_depth)
		{
			matched_entry = node->route;
			max_depth = node->depth;
		}
	}
	return matched_entry;
}

// Classic variant for finding the best possible route.

// struct route_table_entry *get_best_route(uint32_t ip_dest) {
// 	// from lab 4.
// 	struct route_table_entry *best_route = NULL;
// 	uint32_t max_mask = 0;
// 	for (int i = 0; i < routing_table_size; i++) {
// 		if (ntohl(routing_table[i].prefix) == ntohl(ip_dest & routing_table[i].mask)) {
// 			// If a route is found whose prefix matches ip_dest ANDed with the mask, return that route.
// 			// Also check if it has the longest prefix.
// 			if(ntohl(routing_table[i].mask) > ntohl(max_mask)) {
// 				max_mask = routing_table[i].mask;
// 				best_route = &routing_table[i];
// 			}
// 		}
// 	}
// 	printf("best route: %u\n", ntohl(best_route->next_hop));
// 	printf("mask: %u\n", ntohl(best_route->mask));
// 	return best_route;
// }

void send_icmp(size_t interface, char *buffer, uint8_t mtype, uint8_t mcode, int num_bits, uint16_t id, uint16_t seq)
{
	uint8_t *icmp_packet = malloc(600);
	uint32_t current_router_ip = (uint32_t)inet_addr(get_interface_ip(interface));

	struct ether_hdr *eth_part = (struct ether_hdr *)icmp_packet;
	struct ip_hdr *ip_part = (struct ip_hdr *)(icmp_packet + ETHER_HDR_LEN);
	struct icmp_hdr *icmp_part = (struct icmp_hdr *)(icmp_packet + ETHER_HDR_LEN + IP_HDR_LEN);

	// Ethernet header of the original packet from the buffer
	struct ether_hdr *eth_header = (struct ether_hdr *)buffer;
	struct ip_hdr *ip_header = (struct ip_hdr *)(buffer + ETHER_HDR_LEN);

	memcpy(eth_part->ethr_dhost, eth_header->ethr_shost, 6);
	uint8_t current_router_mac[6];
	get_interface_mac(interface, current_router_mac);
	memcpy(eth_part->ethr_shost, current_router_mac, 6);
	eth_part->ethr_type = htons(0x0800);

	// IP header: swap source and destination addresses
	ip_part->dest_addr = ip_header->source_addr;
	ip_part->source_addr = current_router_ip;
	ip_part->checksum = 0;
	ip_part->checksum = checksum((uint16_t *)ip_part, IP_HDR_LEN);
	ip_part->proto = 1; // ICMP protocol
	ip_part->tot_len = htons(IP_HDR_LEN + ICMP_HDR_LEN);
	ip_part->ttl = 64;

	// ICMP header
	icmp_part->mtype = mtype;
	icmp_part->mcode = mcode;
	icmp_part->check = 0;
	icmp_part->check = checksum((uint16_t *)icmp_part, ICMP_HDR_LEN);
	icmp_part->un_t.echo_t.id = id;
	icmp_part->un_t.echo_t.seq = seq;

	// ICMP packet contains the IPv4 header and the first 64 bits after the IPv4 header
	memcpy(icmp_part + ICMP_HDR_LEN, ip_header, IP_HDR_LEN);
	memcpy(icmp_part + ICMP_HDR_LEN + IP_HDR_LEN, buffer + ETHER_HDR_LEN + IP_HDR_LEN, num_bits);

	send_to_link(ETHER_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN, (char *)icmp_packet, interface);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	routing_table = malloc(sizeof(struct route_table_entry) * 90000);
	// subsequently executed in the following format:
	// ./router rtable0.txt rr-0-1 r-0 r-1 => I read from argv[1].
	routing_table_size = read_rtable(argv[1], routing_table);

	arp_table = malloc(sizeof(struct arp_table_entry) * 100);
	arp_table_size = 0;
	// Initially, ARP table is empty.
	packets_queue = create_queue();
	Tree tree = NodeAllocation(-2);
	insert_all(tree, routing_table, routing_table_size);

	while (1)
	{
		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len); // => the interface from which the packet was received.
		DIE(interface < 0, "recv_from_any_links");
		// STEP 1: Implement the router forwarding logic

		/*  Note that packets received are in network order,
		any header field which has more than 1 byte will need to be converted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link.  */

		// Target MAC addr | Source MAC addr | Ether Type, and after this will be the payload
		// (i.e. the encapsulation with IPv4).
		uint32_t ip_current_router = (uint32_t)inet_addr(get_interface_ip(interface));

		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
		// The above protocols are "stacked one after another."
		// Check if the packet has ether_type IPv4.
		if (ntohs(eth_hdr->ethr_type) == 0x0800)
		{
			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + ETHER_HDR_LEN);
			// First, check if the packet sent (apparently a classic IPv4) is actually so, or if it is in fact an ICMP request.
			// So below I check if the proto field in ip_hdr is 1!
			struct icmp_hdr *icmp_part = (struct icmp_hdr *)(buf + ETHER_HDR_LEN + IP_HDR_LEN);
			if (ip_hdr->proto == 1 && icmp_part->mcode == 0 && icmp_part->mtype == 8 && ip_hdr->dest_addr == (uint32_t)(inet_addr(get_interface_ip(interface))))
			{
				// ICMP packet addressed to the router (Echo Request)
				printf("I have an echo request destinated to this router.\n");
				uint16_t id = ntohs(icmp_part->un_t.echo_t.id);
				uint16_t seq = ntohs(icmp_part->un_t.echo_t.seq);
				send_icmp(interface, buf, 0, 0, sizeof(buf + ETHER_HDR_LEN + IP_HDR_LEN), id, seq);
				// I've sent the echo reply, and I will move forward and process the other packets.
				continue;
			}

			struct route_table_entry *best_route = find_longest_prefix_match(tree, ip_hdr->dest_addr);
			if (!best_route)
			{
				printf("I did not find any route for ip: %u\n", ntohl(ip_hdr->dest_addr));
				send_icmp(interface, buf, 3, 0, 64, 1, 1);
				continue;
			}

			// check the checksum
			uint16_t old_checksum = ip_hdr->checksum;
			// set to 0 before, calculating it correctly.
			ip_hdr->checksum = 0;
			uint16_t received_checksum = checksum((uint16_t *)ip_hdr, IP_HDR_LEN);
			if (received_checksum != ntohs(old_checksum))
				continue;
			ip_hdr->checksum = htons(received_checksum);

			ip_hdr->ttl--;
			if (ip_hdr->ttl <= 0)
			{
				printf("ttl e mai mic ca 0");
				// send an ICMP using the created function, and for id and seq I use some random values (I chose 1)
				send_icmp(interface, buf, 11, 0, 64, 1, 1);
				continue;
			}
			ip_hdr->checksum = 0;

			uint16_t checksum_recomputed = checksum((uint16_t *)ip_hdr, IP_HDR_LEN);
			ip_hdr->checksum = htons(checksum_recomputed);
			// I recalculated the checksum because I modified the TTL, and when retransmitting to the next hop
			// the current packet, the new checksum was always set to 0x00 :((

			uint8_t destination_mac[6];
			int found = 0;
			for (int i = 0; i < arp_table_size; i++)
			{
				if (arp_table[i].ip == best_route->next_hop)
				{
					found = 1;
					memcpy(destination_mac, arp_table[i].mac, 6);
					break;
				}
			}
			// if the MAC address of the next-hop exists in the ARP table => send the packet with the populated data.
			if (found == 1)
			{
				// put in the Ethernet header the destination MAC address of the previously found next hop.
				memcpy(eth_hdr->ethr_dhost, destination_mac, 6);
				uint8_t router_mac_addr[6];
				get_interface_mac(interface, router_mac_addr);
				memcpy(eth_hdr->ethr_shost, router_mac_addr, 6);

				send_to_link(len, buf, best_route->interface);
				printf("I send the packet on this interface: %d\n", best_route->interface);
			}
			// If it does not exist in the ARP table cache, I need to send an ARP request to
			// determine the MAC address of the next hop.
			else
			{
				// place the packet in the queue if best_route->next_hop is valid
				struct queue_packet *packet_to_enqueue = malloc(sizeof(struct queue_packet));
				packet_to_enqueue->buf = malloc(len); // aloc memorie pt a pune pachetul in coada.
				memcpy(packet_to_enqueue->buf, buf, len);
				packet_to_enqueue->next_hop = best_route->next_hop;
				packet_to_enqueue->interface = best_route->interface;
				// the interface of the router that sends a request.
				// I need to store it, so that when I receive a reply I know where to send it; I saved it here
				// when I get the reply, I know on which interface to send the IPv4 packet.

				packet_to_enqueue->len = len;
				// enqueue the current packet.
				queue_enq(packets_queue, packet_to_enqueue);
				printf("I've enqueued the packet.\n");

				// I create the ARP packet that I want to send further in order to find out the MAC address, I will make a request.
				uint8_t arp_packet[ETHER_HDR_LEN + ARP_HDR_LEN];
				struct ether_hdr *ethernet_part = (struct ether_hdr *)arp_packet;
				struct arp_hdr *arp_part = (struct arp_hdr *)(arp_packet + ETHER_HDR_LEN);

				ethernet_part->ethr_type = htons(0x0806);
				memset(ethernet_part->ethr_dhost, 0xff, 6); // the broadcast
				get_interface_mac(interface, ethernet_part->ethr_shost);

				// populate the header.
				arp_part->opcode = htons(1);
				arp_part->hw_len = 6;
				arp_part->proto_len = 4;
				arp_part->proto_type = htons(0x0800);
				arp_part->hw_type = htons(1);
				// set as source MAC address, the MAC address of the current router interface.
				get_interface_mac(best_route->interface, arp_part->shwa);
				// the destination MAC address will be 0x00 because here I expect to later parse the reply for an address that I am currently searching for.
				memset(arp_part->thwa, 0x00, 6);
				arp_part->sprotoa = (uint32_t)(inet_addr(get_interface_ip(best_route->interface)));
				// the destination IP address will be the IP address of the next hop
				arp_part->tprotoa = best_route->next_hop;
				// send the request
				send_to_link(ETHER_HDR_LEN + ARP_HDR_LEN, (char *)arp_packet, best_route->interface);
			}
		}
		else if ((ntohs(eth_hdr->ethr_type)) == 0x0806)
		{
			struct arp_hdr *arp_part_arp_packet = (struct arp_hdr *)(buf + ETHER_HDR_LEN);

			// if this router actually receives a reply packet, then I process the packet
			// and update the ARP table.
			if (ntohs(arp_part_arp_packet->opcode) == 2)
			{
				// if it's a reply, I store the IP and MAC address from the sender part of the received ARP reply.
				arp_table[arp_table_size].ip = arp_part_arp_packet->sprotoa;
				memcpy(arp_table[arp_table_size].mac, arp_part_arp_packet->shwa, 6);
				arp_table_size++;
				while (!queue_empty(packets_queue))
				{
					printf("I'm in the packet queue.\n");
					int found = 0;
					struct queue_packet *dequeued_packet = (struct queue_packet *)queue_deq(packets_queue);
					if (!dequeued_packet)
					{
						continue;
					}
					// if this IP address has a corresponding MAC address in the ARP table => OK, I send the packet directly to the destination MAC of its next hop.
					u_int8_t mac_found[6];
					for (int i = 0; i < arp_table_size; i++)
					{
						if (dequeued_packet->next_hop == arp_table[i].ip)
						{
							// if the keys match => store the MAC address from this key.
							memcpy(mac_found, arp_table[i].mac, 6);
							found = 1;
							break;
						}
					}
					// send the dequeued packet whose MAC address I now find in the ARP cache.
					if (found == 1)
					{
						// this means that I know the destination MAC address of the next hop => I send it on the interface
						// FROM WHICH IT CAME TO ME. Let's say the queue looks like this: packet_00 packet_01, packet_02,
						// where packet_00 was the first packet put in the queue
						// HERE I WAS MAKING THE MISTAKE of working with the simple buf, which was the buffer
						// of the arp reply, but I needed to work with the packet dequeued from the queue. =>
						// I updated the queue_packet structure to also store the current buf.
						struct ether_hdr *ethernet_part_dequeued_packet = (struct ether_hdr *)dequeued_packet->buf;
						// the IP part does not interest me at the moment.
						uint8_t mac_router_to_send[6];

						// I retrieve the MAC address corresponding to the interface on which the original packet was supposed to be sent.
						get_interface_mac(dequeued_packet->interface, mac_router_to_send);
						// and I set it as the source hardware address.
						memcpy(ethernet_part_dequeued_packet->ethr_shost, mac_router_to_send, 6);
						// and I send it with the Ethernet protocol, setting as destination the MAC address of the next hop found above.
						memcpy(ethernet_part_dequeued_packet->ethr_dhost, mac_found, 6);
						send_to_link(dequeued_packet->len, (char *)dequeued_packet->buf, dequeued_packet->interface);
					}
					else
					{
						// I did not find the MAC address of the packet dequeued from the queue, so I put it back in the queue.
						queue_enq(packets_queue, dequeued_packet);
						printf("I put it back and continue.");
					}
					free(dequeued_packet->buf);
					free(dequeued_packet);
				}
			}
			else if (ntohs(arp_part_arp_packet->opcode) == 1)
			{
				// an ARP request is sent from a VM to my router =>..
				arp_table[arp_table_size].ip = arp_part_arp_packet->sprotoa;
				memcpy(arp_table[arp_table_size].mac, arp_part_arp_packet->shwa, 6);
				arp_table_size++;

				// if it's a request, then I need to send a reply.
				// so I need to fill in the reply packet.
				uint8_t mac_router_curent[6];
				get_interface_mac(interface, mac_router_curent);
				struct ether_hdr *ethernet_part = (struct ether_hdr *)buf;
				struct arp_hdr *arp_part = (struct arp_hdr *)(buf + ETHER_HDR_LEN);

				uint8_t shwa_curent[6];
				get_interface_mac(interface, shwa_curent);
				// source mac address -> my mac address as the router.
				memcpy(ethernet_part->ethr_shost, shwa_curent, 6);
				// destination MAC address -> MAC address of the VM that sent me the request (since I want to reply to it)
				memcpy(ethernet_part->ethr_dhost, arp_part_arp_packet->shwa, 6);

				memcpy(arp_part->thwa, arp_part->shwa, 6);
				memcpy(arp_part->shwa, shwa_curent, 6);
				arp_part->opcode = htons(2); // for an arp reply type.
				arp_part->hw_type = htons(1);
				// source IP address of the ARP reply packet -> IP address of my router.
				arp_part->sprotoa = ip_current_router;
				// destination IP, it's the IP address of the VM that sent me the request.
				memcpy((uint8_t *)&arp_part->tprotoa, (uint8_t *)&arp_part->sprotoa, 4);
				// I nicely send the packet on the interface from which it was received.
				send_to_link(ETHER_HDR_LEN + ARP_HDR_LEN, (char *)buf, interface);
			}
		}
	}
}