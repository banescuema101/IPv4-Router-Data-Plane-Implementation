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


















## Pentru partea de populare dinamica a cahe-ului arp initial gol, 
In cazul in care primeam un pachet ipv4 (adica in headerul de ethernet parsat mie tipul era 0x080): => prima data
cautam in tabela (vector de structuri de ip- mac, asocieri intre cele doua), daca adresei ip
pe care vrea pachetul primit sa ajunga in retea, ii cunosc in primul rand adresa hardware.
Aici am doua cazuri:

1) daca o cunosc, trimit direct pe interfata corespunzatoare celei mai bune rute gasite.
2) in caz contrar, fac un arp request catre toate dispozitivele din reteaua ROUTERULUI, populand conform instructiunilor din cerinta, cat si de pe youtube, campurile headerului arp, dar avand grija sa plasez si pachetul ipv4 original in coada. La un reply, scoteam fiecare pachet din coada
si puteam sa am 2 cazuri: in care acum stiu la ce adresa mac sa trimit, caz in care pur si simplu trimiteam, si al doilea caz in care adresa mac destinatie corespunzatoare adresei ipv4 a pachetului original tot nu exista in tabela arp dinamica, caz in care pun pachetul inapoi in coada! `   :)	` mai sta si asteapta si el..

## Cum am format structura pachetului arp?
Practic o zona de memorie de dimensiune cat suma structurilor celor doua headere ether_hdr si arp_hdr, in care ca sa populez campurile ambelor headere, doar ,,impart" pachetul in 2 sub-parti: una care pointeaza catre inceputul pachetului, si una care puncteaza catre pachet + dim_headerului_ethernet -> de aici incepand practic sectiunea headerului arp_hdr.

# OBS 
Pentru a popula un camp de tip uint32_t, o adresa ip corespunzatoare unei anumite interfete, am folosit functia inet_addr, pentru a converti un char* intr-un uint32_t.

# OBS
Aici facusem prostia ca atunci cand puneam pachetul original in coada, sa nu retin si efectiv
datele lui concrete, memorasem decat next_hopul, interface-ul si mac-ul, astfel incat sa stiu cand ma intorc cu reply-uri, pe ce interfata sa il trimit (cand primeam un reply, trebuie interfata best_route->interface a pachetului original, nu interfata de pe care a venit reply-ul evident) si sa stiu si care este efectiv mac-ul si adresa la care sa il trimit.

Am observat ca faceam o greseala pt. ca nu tineam minte si datele lui efective, precum si lungimea datelor ( adica bufferul original), si eu trimiteam cu bufferul reply-ului cand imi venea la router. Asa ca am introdus si campurile *buf si len in structura pachet_coada.

## Pentru partea de icmp:
Aici mi-am creat o functie separata, in care puteam sa variez urmatorii parametrii:
	- mtype
	- mcode
	- numar_biti
 	  Am dat ca parametru si interfata pe care sa trimit pachetul de tip icmp (va fi interfata de pe care tocmai ce a sosit pachetul original, ori un ipv4 cu probleme la ttl sau la destinatie urmatoare unreachable, ori un icmp request).
	- id si seq  => imi trebuiau pentru ca intr-adevar la un icmp pt ttl sau destination unreachable, nu conta cat am in aceste field-uri, insa la icmp-ul de tip echo reply, da, aici trebuia sa pun exact id-ul si seq-ul pe care le avea icmp-requestul.
In functie creez pachetul icmp: ethernet + cadru ipv4 + partea icmp, care la randul ei are un ipv4 header si ceva biti de date dupa.

# OBSERVATIE
Mi-a luat destul de mult sa imi dau seama de ce ultimele 2 teste mereu picau, si cand le rulam manual, cat si cand rulam cu chekerul. Era din cauza faptului ca eu trimiteam un icmp reply, doar in momentul in care la router ajungea un pachet care avea campul proto din headerul ip setat pe 1, mcode-ul in headerul icmp pe 0, si mtype-ul pe 8 si daca indeplinea aceste conditii atunci ii dadeam un reply.
Ei bine, am mai citit de cateva ori enuntul si m-am gandit sa ii mai pun o conditie suplimentara, anume sa verific si explicit daca adresa ip destinatie din headerul ipv4 coincidea cu cea a routerului meu. DUpa ce am inclus si acesta conditie, a mers.!!! ` :) `

## Partea de Long Prefix Match:

Pentru a eficientiza procesul LPM, pentru a vedea care intrare in tabela de rutare ar descrie o retea ce curpinde adresa primita ca parametru ip_dest, am folosit un arbore binar (fiecare nod are 2 copii, care pot fi 0 respectiv 1, o adancime, si o intrare din tabela de rutare asociata cu el, pentru a putea sti ulterior,cand parcurg in adancime arborele,cand dau de un prefix, sa stiu ce intrare din tabela de rutare are acel nod asociata.)

# OBS:
La materia structuri de date si algoritmi, am avut de implementat un arbore de sufixe (pe siruri de caractere), asa ca am reutilizat cateva functii, doar ca le-am modificat pentru cazul: arbore binar 0/1.

# Cum am procedat?:
Am luat fiecare prefix aferent unei intrari in tabela de routare, si am inserat in arbore ( daca nu exista un nod aferent unui bit, alocam nod nou cu respectiva informatie, altfel, doar ma deplasam spre urmatorul nod de jos - care continea ca informatie acel bit - cu pointerul la radacina Node* nod, mai exact Tree nod).
Aici foarte important este faptul ca nu mi-a mers procesul de cautare daca
inseram fiecare bit din prefix, a trebuit sa inserez exact lungimea mastii mask.

La cautare, dandumi-se o anumita adresa ip, am transformat-o intr-un vector
de biti, mi-am luat un poiinter la arborele creat deja, apoi am iterat prin acel vector de biti, verificand bit cu bit, daca copilul nodului la care indica pointerul de pe ramura din stanga ( in caz ca elementul din vector e 0) sau din dreapta ( caz in care elementul din vector e 1), si retineam adresa asociata. Apoi, coboram un nivel in arbore, mutand pointerul la nodul repsectiv vizitat si procesul etc etc continua pana la final, pana atunci cand dadeam de o frunza. 
In final, am returnat direct adresa_matchuita, care clar e cea mai buna posibila (cel mai lung prefix matchuit posibil), cautarea realizandu-se practic intr-un O(32).
