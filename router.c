#include "lib.h"
#include "protocols.h"
#include "queue.h"
#include <arpa/inet.h>
#include <string.h>

struct route_table_entry *get_best_route_binary(uint32_t ip_dest, int rtable_len, struct route_table_entry *rtable)
{
	int left = 0, right = rtable_len - 1;
	struct route_table_entry *best_match = NULL;

	while (left <= right) {
		int mid = left + (right - left) / 2;
		if ((ip_dest & rtable[mid].mask) == rtable[mid].prefix) {
			best_match = &rtable[mid];
			right = mid - 1;
		} else if ((ip_dest & rtable[mid].mask) > rtable[mid].prefix) {
			right = mid - 1;
		} else {
			left = mid + 1;
		}
	}

	return best_match;
}

struct arp_table_entry *find_corresponding_mac(struct arp_table_entry *mac_table, int mac_table_len, uint32_t ip)
{
	struct arp_table_entry *end = mac_table + mac_table_len;
	for (struct arp_table_entry *entry = mac_table; entry != end; ++entry) {
		if (entry->ip == ip) {
			return entry;
		}
	}

	return NULL;
}

int compare(const void *a, const void *b)
{
	struct route_table_entry *entry_a = (struct route_table_entry *)a, *entry_b = (struct route_table_entry *)b;

	if (entry_a->prefix != entry_b->prefix) {
		return entry_b->prefix - entry_a->prefix;
	}

	return entry_b->mask - entry_a->mask;
}

void sort_rtable(struct route_table_entry *rtable, size_t size)
{
	qsort(rtable, size, sizeof(struct route_table_entry), compare);
}

void send_icmp(struct ether_header *current_eth_hdr, struct iphdr *current_ip_hdr, int interface, uint8_t type)
{
	char buf[MAX_PACKET_LEN];
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	memcpy(eth_hdr->ether_dhost, current_eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, current_eth_hdr->ether_dhost, 6);
	eth_hdr->ether_type = current_eth_hdr->ether_type;

	ip_hdr->ihl = current_ip_hdr->ihl;
	ip_hdr->version = current_ip_hdr->version;
	ip_hdr->tos = current_ip_hdr->tos;
	if (type == 0) {
		ip_hdr->tot_len = current_ip_hdr->tot_len;
	} else {
		ip_hdr->tot_len = htons(sizeof(struct iphdr) * 2 + sizeof(struct icmphdr) + 8);
	}
	ip_hdr->id = htons(ntohs(current_ip_hdr->id) + 1);
	ip_hdr->frag_off = current_ip_hdr->frag_off;
	ip_hdr->ttl = current_ip_hdr->ttl;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->saddr = current_ip_hdr->daddr;
	ip_hdr->daddr = current_ip_hdr->saddr;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	if (type == 0) {
		send_to_link(interface, buf, sizeof(struct ether_header) + ntohs(ip_hdr->tot_len));
	} else {
		memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), current_ip_hdr,
			   sizeof(struct iphdr));
		memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) * 2 + sizeof(struct icmphdr),
			   current_ip_hdr + sizeof(struct iphdr), 8);
		send_to_link(interface, buf,
					 sizeof(struct ether_header) + sizeof(struct iphdr) * 2 + sizeof(struct icmphdr) + 8);
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 66666);
	int rtable_len = read_rtable(argv[1], rtable);
	sort_rtable(rtable, rtable_len);

	struct arp_table_entry *mac_table = malloc(sizeof(struct arp_table_entry) * 10);
	int mac_table_len = parse_arp_table("arp_table.txt", mac_table);

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		char *interface_ip = get_interface_ip(interface);
		uint32_t interface_ip_int;
		inet_pton(AF_INET, interface_ip, &interface_ip_int);

		if (ip_hdr->daddr == interface_ip_int) {
			send_icmp(eth_hdr, ip_hdr, interface, 0);
		} else {
			uint16_t current_checksum = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			uint16_t new_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

			if (new_checksum == current_checksum) {
				if (ip_hdr->ttl <= 1) {
					send_icmp(eth_hdr, ip_hdr, interface, 11);
				} else {
					ip_hdr->ttl--;

					struct route_table_entry *best_route = get_best_route_binary(ip_hdr->daddr, rtable_len, rtable);
					if (best_route == NULL) {
						send_icmp(eth_hdr, ip_hdr, interface, 3);
					} else {
						ip_hdr->check = 0;
						ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

						struct arp_table_entry *mac =
							find_corresponding_mac(mac_table, mac_table_len, best_route->next_hop);
						memcpy(eth_hdr->ether_dhost, mac->mac, 6);
						get_interface_mac(best_route->interface, eth_hdr->ether_shost);

						send_to_link(best_route->interface, buf, len);
					}
				}
			}
		}
	}
}
