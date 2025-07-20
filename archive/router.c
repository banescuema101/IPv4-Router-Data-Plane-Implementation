#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

struct route_table_entry *tabela_rutare;
int tabela_rutare_size;
struct arp_table_entry *tabela_arp;
int tabela_arp_size;
struct queue *coada_pachete;

struct pachet_coada {
	uint32_t next_hop;
	size_t interface;
	uint8_t mac[6];
	uint8_t *buf;
	size_t len;
};
typedef struct node {
	struct node* children[2]; 
	// 2 posibili copii, ca-i arbore binar.
	uint32_t next_hop;
	struct route_table_entry* route; 
	int deep; 
	// inaltimea pe care se afla un nod in arbore.
	int info; 
	// 0 sau 1.
} Node, *Tree;

Tree AlocaNod(int info) {
	Tree nod = malloc(sizeof(Node));
	if(!nod) {
		return NULL;
	}
	nod->children[0] = NULL;
	nod->children[1] = NULL;
	nod->deep = 0;
	nod->info = info;
	nod->route = NULL;
	return nod;
}
int* transforma_ip_in_binar(uint32_t ip) {
	int *array_binar = malloc(sizeof(int) * 32);
	for (int i = 0; i < 32; i++) {
		array_binar[i] = (ip >> (31 - i)) & 1;
	}
	return array_binar;
}
int calcul_lungime_prefix(uint32_t mask) {
	int count = 0;
	for (int i = 0; i < 32; i++) {
		if (mask & (1 << (31 - i))) {
			count++;
		} else {
			break; 
		}
	}
	return count;
}
void insereaza(Tree arbore, struct route_table_entry* entry) {
	Tree nod = arbore;
	int *array_binar = transforma_ip_in_binar(ntohl(entry->prefix));
	int lungime_prefix = calcul_lungime_prefix(ntohl(entry->mask));
	for (int i = 0; i < lungime_prefix; i++) {
		if (array_binar[i] == 0) {
			if (nod->children[0] == NULL) {
				nod->children[0] = AlocaNod(0);
				nod->children[0]->deep = nod->deep + 1;
			}
			nod = nod->children[0]; // daca deja e alocat nodul cu bitul 0,
			// doar ma duc pe ramura lui.
		} else {
			if (nod->children[1] == NULL) {
				nod->children[1] = AlocaNod(1);
				nod->children[1]->deep = nod->deep + 1;
			}
			nod = nod->children[1];
		}
	}
	nod->route = entry;
}
void insert_all(Tree arbore, struct route_table_entry* tabela_rutare, int size) {
	for (int i = 0; i < size; i++) {
		insereaza(arbore, &tabela_rutare[i]);
	}
}
void printeaza_arbore(Tree arbore) {
	if (arbore == NULL) {
		return;
	}
	printf("Nodul curent are info: %d, adica %d\n", arbore->info, arbore->deep);
	printeaza_arbore(arbore->children[0]);
	printeaza_arbore(arbore->children[1]);
}
struct route_table_entry* cauta_long_prefix_match(Tree arbore, uint32_t ip_dest) {
	int* array_binar = transforma_ip_in_binar(ntohl(ip_dest));
	struct route_table_entry* adresa_matchuita = NULL;

	Tree nod = arbore;
    for (int i = 0; i < 32; i++) {
        int bit = array_binar[i];
		// daca nu mai are copii, am ajuns la frunza => ma opresc si returnez ce am gasit pana acum, daca am gasit ceva
        if (nod->children[array_binar[i]] == NULL) {
            break;
        }
		// deplasare ori pe ramura stanga, ori pe dreapta
		if (array_binar[i] == 0) {
			nod = nod->children[0];
		} else {
			nod  = nod->children[1];
		}
		// aici se va intra prima data la primul copil al radacinii, si tot asa etc etc
        if (nod->route != NULL) {
            adresa_matchuita = nod->route;  // retin ultimul prefix bun pe care l-am obtinut
        }
    }
    return adresa_matchuita;
}

// varianta clasica de gasire a celei mai bune rute posibile.

// struct route_table_entry *get_best_route(uint32_t ip_dest) {
// 	// from lab 4.
// 	struct route_table_entry *best_route = NULL;
// 	uint32_t max_mask = 0;
// 	for (int i = 0; i < tabela_rutare_size; i++) {
// 		if (ntohl(tabela_rutare[i].prefix) == ntohl(ip_dest & tabela_rutare[i].mask)) {
// 		// daca am gasit o ruta care are prefixul egal cu ip_dest SI LOGIC cu masca, atunci returnez acea ruta.
// 	    // verific si ca ar fi cu cel mai lung prefix.
// 			if(ntohl(tabela_rutare[i].mask) > ntohl(max_mask)) {
// 				max_mask = tabela_rutare[i].mask;
// 				best_route = &tabela_rutare[i];
// 			}
// 		}
// 	}
// 	printf("best route-ul: %u\n", ntohl(best_route->next_hop));
// 	printf("masca: %u\n", ntohl(best_route->mask));
// 	return best_route;
// }
void trimite_icmp(size_t interface, char* buffer, uint8_t mtype, uint8_t mcode, int numar_biti, uint16_t id, uint16_t seq) {
	uint8_t *pachet_icmp = malloc(600);

	struct ether_hdr *parte_ether = (struct ether_hdr *)pachet_icmp;
	struct ip_hdr *parte_ip = (struct ip_hdr *)(pachet_icmp + sizeof(struct ether_hdr));
	struct icmp_hdr *parte_icmp = (struct icmp_hdr *)(pachet_icmp + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	// substrat de ethernet
	// am nevoie intai de ethernet headerul al pachetului din bufferul buffer, cat si de partea lui de ip, adica
	// ale pachetului initial.
	struct ether_hdr *header_eth = (struct ether_hdr *)buffer;
	struct ip_hdr *header_ip = (struct ip_hdr *)(buffer + sizeof(struct ether_hdr));
	memcpy(parte_ether->ethr_dhost, header_eth->ethr_shost, 6);
	uint8_t mac_router_curent[6];
	get_interface_mac(interface, mac_router_curent);
	memcpy(parte_ether->ethr_shost, mac_router_curent, 6);
	parte_ether->ethr_type = htons(0x0800);
	// partea de icmp cu cele 3 caracteristici: 
	// pun in parte ip fix headerul de ip dar modficat, dar adresle sursa/ destinatie inversate.
	parte_ip->dest_addr = header_ip->source_addr;
	parte_ip->source_addr = inet_addr(get_interface_ip(interface));
	parte_ip->checksum = 0;
	parte_ip->checksum = checksum((uint16_t *)parte_ip, sizeof(struct ip_hdr));
	parte_ip->proto = 1; // pentru icmp.
	parte_ip->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr)); // ca vreau sa il contina.
	parte_ip->ttl = 64; // partea de icmp.
	parte_icmp->mtype = mtype;
	parte_icmp->mcode = mcode;
	parte_icmp->check = 0;
	parte_icmp->check = checksum((uint16_t *)parte_icmp, sizeof(struct icmp_hdr));
	// le pun si pe asta. Intr-adevar la ttl si unreachable host nu am nevoie de ceva valori aici
	// dar eu vreau sa le pun pentru testul de ECHO REQUEST.
	parte_icmp->un_t.echo_t.id = id;
	parte_icmp->un_t.echo_t.seq = seq;
	// dar pachetul icmp contine in interiorul lui, pe langa header
	// si headerul ipv4, cat si primiii 64 de biti de dupa acel ipv4 header.
	memcpy(parte_icmp + sizeof(struct icmp_hdr), header_ip, sizeof(struct ip_hdr));
	// mi am pus mai jos, primii 64 de biti de deasupra ipv4.
	memcpy(parte_icmp + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr), buffer + sizeof(struct ether_hdr) + sizeof(struct ip_hdr), 64);
	send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), (char *)pachet_icmp, interface);

}
int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	tabela_rutare = malloc(sizeof(struct route_table_entry) * 90000);
	// executandu-se ulterior in urmatorul format:
	// ./router rtable0.txt rr-0-1 r-0 r-1 => citesc din argv[1].
	tabela_rutare_size = read_rtable(argv[1], tabela_rutare);

	tabela_arp = malloc(sizeof(struct arp_table_entry) * 100);
	tabela_arp_size = 0;
	// initial tabela arp e goala.
	coada_pachete = create_queue();
	Tree arbore = AlocaNod(-2);
	insert_all(arbore, tabela_rutare, tabela_rutare_size);


	while (1) {
		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len); // => interfata routerului
		DIE(interface < 0, "recv_from_any_links");
		// TODO: Implement the router forwarding logic

    	/*  Note that packets received are in network order,
			any header field which has more than 1 byte will need to be converted to
			host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
			sending a packet on the link.  */

		// Mac Destinatie | Mac Sursa | Ether Type , dupa urmeaza payloadul (adica fix encapsularea cu IPV4).
		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
		// protocoalele de mai sus fiind ,,stivuite unul dupa celalat."
		// verific daca este un pachet cu ether_type IPv4.
		if (ntohs(eth_hdr->ethr_type) == 0x0800) {
			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
			// verific intai daca nu cumva pacehtul trimis ( aparent un clasic ipv4 este chiar asa, sau daca este defat un ICMP request)
			// deci mai jos verific daca campul proto in ip_hdr este 1 !
			struct icmp_hdr *icmp_part = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
			printf("proto al ipv4-ului este: %u\n", ip_hdr->proto);
			if (ip_hdr->proto == 1 && icmp_part->mtype == 8 && icmp_part->mcode == 0) {
				printf("am intart aici off ce ma enerveaza");
				uint16_t id = ntohs(icmp_part->un_t.echo_t.id);
				uint16_t seq = ntohs(icmp_part->un_t.echo_t.seq);
				trimite_icmp(interface, buf, 0, 0, sizeof(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr)), id, seq);
			}
			int* array = transforma_ip_in_binar(ip_hdr->dest_addr);
			struct route_table_entry *best_route = cauta_long_prefix_match(arbore, ip_hdr->dest_addr);
			if (!best_route) {
				printf("nu am gasit nicio ruta pentru ip-ul; %u\n", ntohl(ip_hdr->dest_addr));
				trimite_icmp(interface, buf, 3, 0, 64, 1, 1);
				continue;
			}

			// daca in campul ethernet, ip-ul destinatie e fix ip-ul de pe interfata curenta a routerului
			// procedez ca la un pachet normal, doar il arunc, chiar daca ttl ar fi 0 ..
			if (inet_addr(get_interface_ip(interface)) == ip_hdr->dest_addr) {
				continue;
			}
			// verific checksum-ul.
			uint16_t old_checksum = ip_hdr->checksum;
			// fac inainte 0 pt a o calcula cum trebuie (preluare din labul 4)
			ip_hdr->checksum = 0;
			uint16_t received_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));
			if(received_checksum != ntohs(old_checksum))
				continue;
			ip_hdr->checksum = htons(received_checksum);

			ip_hdr->ttl--;
			if (ip_hdr->ttl <= 0) {
				printf("ttl e mai mic ca 0");
				// trimit un icmp folosind functia creata, si pe post pe id si seq pun niste valori random(am ales 1)
				trimite_icmp(interface, buf, 11, 0, 64, 1, 1);
				continue;
			}
			ip_hdr->checksum = 0;
			uint16_t checksum_recalculat = checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));
			ip_hdr->checksum = htons(checksum_recalculat);
			// am recalculat checksum-ul intrucat modific ttl-ul, si cand retransmiteam la urmatorul hop
			// pachetul curent, mi se punea la checksum nou mereu 0x00 :(((

			uint8_t mac_destinatie[6];
			int gasit = 0;
			for (int i = 0; i < tabela_arp_size; i++) {
				if (tabela_arp[i].ip == best_route->next_hop) {
					gasit = 1;
					memcpy(mac_destinatie, tabela_arp[i].mac, 6);
					printf("am gasit mac-ul in tabela de arp: %u:%u:%u:%u:%u:%u\n", mac_destinatie[0], mac_destinatie[1], mac_destinatie[2], mac_destinatie[3], mac_destinatie[4], mac_destinatie[5]);
					break;
				}
			}
			// daca adresa mac a next-hopului exista in tabela arp => trimit pachetul cu datele populate.
			if (gasit == 1) {
				// pun in headerul de Ethernet adresa mac destinatie a hopului gasit precedent.
				memcpy(eth_hdr->ethr_dhost, mac_destinatie, 6);
				uint8_t router_mac_addr[6];
				get_interface_mac(interface, router_mac_addr);
				memcpy(eth_hdr->ethr_shost, router_mac_addr, 6);

				send_to_link(len, buf, best_route->interface);
				printf("Sending packet to interface %d\n", best_route->interface);
			} // Daca nu exista in cahch-ul tabelei arp trebuie sa fac un arp_request sa iau determin mac-ul next-hopului.
			else {
				// plasez pachetul in coada daca best_route->next_hop e valid
				struct pachet_coada *pachet_de_pus = malloc(sizeof(struct pachet_coada));
				pachet_de_pus->buf = malloc(len); // aloc memorie pt a pune pachetul in coada.
				memcpy(pachet_de_pus->buf, buf, len);
				pachet_de_pus->next_hop = best_route->next_hop;
				pachet_de_pus->interface = best_route->interface;
				// interfata routerului care trimite un request.
				// trebuie sa o pun, astfel incat cand ma intorc cu un reply sa stiu pe unde o trimit, am memorat-o aici
				// cand ma intorc stiu pe ce interfata sa trimit pachetul ipv4.

				pachet_de_pus->len = len;
				// pun in coada pachetul curent.
				queue_enq(coada_pachete, pachet_de_pus);
				printf("Am pus pachetul in coada\n");

				// formez pachetul arp pe care vreau sa il trimit mai departe ca sa alfu macul, voi face un request.
				uint8_t pachet_arp[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)];
				struct ether_hdr *parte_eth = (struct ether_hdr *)pachet_arp;
				struct arp_hdr *parte_arp = (struct arp_hdr *)(pachet_arp+ sizeof(struct ether_hdr));
				
				parte_eth->ethr_type = htons(0x0806);
				memset(parte_eth->ethr_dhost, 0xff, 6); // Broadcast
				get_interface_mac(interface, parte_eth->ethr_shost);
			
				// populez headerul.
				parte_arp->opcode = htons(1);
				parte_arp->hw_len = 6;
				parte_arp->proto_len = 4;
				parte_arp->proto_type = htons(0x0800);
				parte_arp->hw_type = htons(1);
				// pun ca adresa mac sursa, adresa mac a interfetei routerului curent.
				get_interface_mac(best_route->interface, parte_arp->shwa);
				parte_arp->sprotoa = inet_addr(get_interface_ip(best_route->interface));
				// adresa mac destinatie va fi 0x00 intrucat aici ma astept ulterior sa imi parseze reply-ul o adresa pe care eu o caut acum.
				memset(parte_arp->thwa, 0x00, 6);
				// adresa ip destinatie va fi adresa ip a urmatorului hop
				parte_arp->tprotoa = best_route->next_hop;
			
				// trimit requestul 
				send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), (char*)pachet_arp, best_route->interface);
				}
			} else if ((ntohs(eth_hdr->ethr_type)) == 0x0806) {
				// aici pusesem din greseala la sizeof, sizeof(eth_hdr) in loc de sizeof(struct ether_hdr)
				// 2 ZILE DE DEBUGGGGGGGGGG UGHHHHHHHHHHH. :((((((  ofofofoofof doamne. 
				// SI in loc sa mi se deplaseze cu cat era structura
				// defapt imi lua intreaga dimensiune a protocolului ethernet a unui pachet anterior procesat
				struct arp_hdr *parte_arp_pachet_arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));


				uint32_t ip_router_curent = inet_addr(get_interface_ip(interface));
				// daca acest router primeste defapt un pachet de reply, atunci procesez pachetul
				// si completez tabela de arp.
				if (ntohs(parte_arp_pachet_arp->opcode) == 2) {  // daca e un reply memorez adresa ip si mac din partea de sender din reply-ul arp primit.
					tabela_arp[tabela_arp_size].ip = parte_arp_pachet_arp->sprotoa;
					memcpy(tabela_arp[tabela_arp_size].mac, parte_arp_pachet_arp->shwa, 6);
					tabela_arp_size++;
					while(!queue_empty(coada_pachete)) {
						printf("Am intrat in coada de pachete\n");
						int gasit = 0;
						struct pachet_coada *pachet_scos = (struct pachet_coada*)queue_deq(coada_pachete);
						if (!pachet_scos) {
							continue;
						}
						// daca adresa aceasta ip are corespondent in adresa mac in arp table => OK, trimit direct pachetul la macul dest al lui next hop.
						u_int8_t mac_gasit[6];
						for (int i = 0; i < tabela_arp_size; i++) {
							if (pachet_scos->next_hop == tabela_arp[i].ip) {
								// daca cheile coincid => memorez mac-ul de la cheia asta.
								memcpy(mac_gasit, tabela_arp[i].mac, 6);
								gasit = 1;
								break;
							}
						}
						// trimit pachetul scos idn coada a carui adresa mac o gasesc in chache ul arp acum.
						if (gasit == 1) {
							// inseamna ca adresa mac destinatie a urmatorului hop o cunosc=>il trimit pe interfata de PE CARE A VENIT LA MINE.
							// coada sa zic ca arata asa: pachet_00 pachet_01, pachet_02 , unde pachet_00 a fost primul pachet pus in coada
							// AICI FACEAM PROSTIA SA lucrez cu buf simplu, care era bufferul arp reply-ului, mie imi
							// trebuia sa lucrez cu pachetul scos din coada. => actualizai in structura de pachet_coada sa retin si buf-ul curent.
							struct ether_hdr* parte_eth_pachet_scos= (struct ether_hdr*)pachet_scos->buf;
							struct ip_hdr* parte_ip_pachet_scos = (struct ip_hdr*)(pachet_scos->buf + sizeof(struct ether_hdr));
							uint8_t mac_router_de_trimis[6];

							// => mac-ul routerului curent.
							get_interface_mac(pachet_scos->interface, mac_router_de_trimis);
							memcpy(parte_eth_pachet_scos->ethr_shost, mac_router_de_trimis, 6);
							// si il trimit ca avand in protocolul ethernet, ca destinatie, mac-ul urmatorului hop bun gasit mai sus.
							memcpy(parte_eth_pachet_scos->ethr_dhost, mac_gasit, 6);
							send_to_link(pachet_scos->len, (char *)pachet_scos->buf, pachet_scos->interface);
						} else {
							// nu am gasit adresa mac a pachetului scos din coada, deci il pun inapoi in coada.
							queue_enq(coada_pachete, pachet_scos);
							printf("il pun la loc si continui.");
						}
						free(pachet_scos->buf);
						free(pachet_scos);
					}
				} else if (ntohs(parte_arp_pachet_arp->opcode) == 1) { // se trimite nu arp request de la un vm catre routerul meu =>..
					tabela_arp[tabela_arp_size].ip = parte_arp_pachet_arp->sprotoa;
					memcpy(tabela_arp[tabela_arp_size].mac, parte_arp_pachet_arp->shwa, 6);
					tabela_arp_size++;

					// daca e un request, atunci trebuie sa ii trimit un reply.
					// deci trebuie sa completez pachetul de reply.
					uint8_t mac_router_curent[6];
					get_interface_mac(interface, mac_router_curent);
					// printf("am intrat in partea in care fac reply\n");
					// printf("MAC-ul routerului curent este: %02x:%02x:%02x:%02x:%02x:%02x\n",
					// 	mac_router_curent[0], mac_router_curent[1], mac_router_curent[2],
					// 	mac_router_curent[3], mac_router_curent[4], mac_router_curent[5]);
					// printf("MAC-ul target al requestului primit este: %02x:%02x:%02x:%02x:%02x:%02x\n",
					// 	parte_arp_pachet_arp->thwa[0], parte_arp_pachet_arp->thwa[1],
					// 	parte_arp_pachet_arp->thwa[2], parte_arp_pachet_arp->thwa[3],
					// 	parte_arp_pachet_arp->thwa[4], parte_arp_pachet_arp->thwa[5]);
						struct ether_hdr *parte_eth = (struct ether_hdr *)buf;
						struct arp_hdr *parte_arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
						uint8_t shwa_curent[6];
						get_interface_mac(interface, shwa_curent);
						memcpy(parte_eth->ethr_shost, shwa_curent, 6);
						memcpy(parte_eth->ethr_dhost, parte_arp_pachet_arp->shwa, 6);
						memcpy(&parte_arp->thwa, parte_arp->shwa, 6);
						memcpy(parte_arp->shwa, shwa_curent, 6);
						parte_arp->opcode = htons(2); // pt arp de tip reply.
						parte_arp->hw_type = htons(1);
						memcpy((uint8_t *)&parte_arp->tprotoa, (uint8_t *)&parte_arp->sprotoa, 4);
						uint32_t ip_reply = inet_addr(get_interface_ip(interface));
						memcpy(&parte_arp->sprotoa, &ip_reply, sizeof(uint32_t));
						send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), (char*)buf, interface);
				}
			}
	}
}