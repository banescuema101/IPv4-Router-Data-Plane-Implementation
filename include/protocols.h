#include <unistd.h>
#include <stdint.h>

/* Ethernet ARP packet from RFC 826 */
struct arp_hdr
{
  uint16_t hw_type;    /* Format of hardware address */
  uint16_t proto_type; /* Format of protocol address */
  uint8_t hw_len;      /* Length of hardware address */
  uint8_t proto_len;   /* Length of protocol address */
  uint16_t opcode;     /* ARP opcode (command) */
  uint8_t shwa[6];     /* Sender hardware address */
  uint32_t sprotoa;    /* Sender IP address */
  uint8_t thwa[6];     /* Target hardware address */
  uint32_t tprotoa;    /* Target IP address */
} __attribute__((packed));

/* Ethernet frame header*/
struct ether_hdr
{
  uint8_t ethr_dhost[6]; // target MAC address
  uint8_t ethr_shost[6]; // sender MAC address
  uint16_t ethr_type;    // encapsulated protocol identifier
};

/* IP Header */
struct ip_hdr
{
  // this means that version uses 4 bits, and ihl 4 bits
  uint8_t ihl : 4, ver : 4; // we use version = 4
  uint8_t tos;              // Not relevant for the project (set on 0)
  uint16_t tot_len;         // total length = ipheader + data
  uint16_t id;              // Not relevant for the project (set to 4)
  uint16_t frag;            // Not relevant for the project, (set on 0)
  uint8_t ttl;              // Time to Live -> to avoid loops, we will decrement
  uint8_t proto;            // Encapsulated protocol identifier (e.g. ICMP)
  uint16_t checksum;        // checksum     -> Since we modify TTL,
  uint32_t source_addr;     // Sender IP address
  uint32_t dest_addr;       // Target IP address
};

struct icmp_hdr
{
  uint8_t mtype;  /* message type */
  uint8_t mcode;  /* type sub-code */
  uint16_t check; /* checksum */
  union
  {
    struct
    {
      uint16_t id;
      uint16_t seq;
    } echo_t;              /* echo datagram. I will use only this field from union.*/
    uint32_t gateway_addr; /* Gateway address. Not relevant for the project */
    struct
    {
      uint16_t __unused;
      uint16_t mtu;
    } frag_t; /* Not relevant for the project */
  } un_t;
};
