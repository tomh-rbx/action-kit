// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// DNS response codes
#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_SERVFAIL 2

// Config flags
#define CONFIG_INJECT_NXDOMAIN 0x01
#define CONFIG_INJECT_SERVFAIL 0x02
#define CONFIG_RANDOM_CHOICE 0x04
#define CONFIG_IS_CONTAINER_MODE 0x08

// Header cursor structure for parsing (Megazord style)
struct hdr_cursor {
	void *pos;
	void *data_end;
};

// Generic IP header for determining IP version
struct geniphdr {
	__u8 version;
};

// DNS header structure
struct dns_header {
	__u16 id;
	__u16 flags;
	__u16 qdcount;
	__u16 ancount;
	__u16 nscount;
	__u16 arcount;
};

// IPv4 LPM Trie key
struct ipv4_lpm_key {
	__u32 prefixlen;
	__u32 addr;
} __attribute__((packed));

// IPv6 LPM Trie key
struct ipv6_lpm_key {
	__u32 prefixlen;
	__u8 addr[16];
};

// Metrics structure
struct metrics_value {
	__u64 seen;
	__u64 ipv4;
	__u64 ipv6;
	__u64 egress_queries;
	__u64 ingress_responses;
	__u64 dns_matched;
	__u64 injected;
	__u64 injected_nxdomain;
	__u64 injected_servfail;
	__u64 ipv4_allowed_called;
	__u64 ipv4_allowed_passed;
	__u32 last_saddr; // diagnostic: last seen source IP (network byte order)
	__u32 last_daddr; // diagnostic: last seen dest IP (network byte order)
	__u32 last_rejected_saddr; // diagnostic: last rejected source IP
	__u32 last_rejected_daddr; // diagnostic: last rejected dest IP
	__u32 last_lookup_src_ne; // diagnostic: last source IP we looked up (network-endian)
	__u32 last_lookup_src_he; // diagnostic: last source IP we looked up (host-endian)
	__u32 last_lookup_dst_he; // diagnostic: last dest IP we looked up (host-endian)
};

// Maps
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} config_map SEC(".maps");

// Use hash map for exact IP matching (more efficient than LPM trie for /32)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} ipv4_cidr_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key, struct ipv6_lpm_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipv6_cidr_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u16);
	__type(value, __u8);
} port_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct metrics_value);
} metrics_map SEC(".maps");

// Megazord-style header parsers

/**
 * parse_ethhdr parses Ethernet header and returns the next protocol
 **/
static __always_inline int parse_ethhdr(struct hdr_cursor *hc, struct ethhdr **ethhdr)
{
	struct ethhdr *eth = hc->pos;

	/* check packet bounds */
	if (hc->pos + sizeof(struct ethhdr) > hc->data_end) {
		return -1;
	}

	hc->pos += sizeof(*eth);
	*ethhdr = eth;

	return eth->h_proto;
}

/* parses IPv4 header and returns the next protocol */
static __always_inline int parse_iphdr(struct hdr_cursor *hc, struct iphdr **iphdr)
{
	struct iphdr *ip = hc->pos;

	if (hc->pos + sizeof(struct iphdr) > hc->data_end) {
		return -1;
	}

	hc->pos += sizeof(*ip);
	*iphdr = ip;

	return ip->protocol;
}

/* parses IPv6 header and returns the next protocol */
static __always_inline int parse_ipv6hdr(struct hdr_cursor *hc, struct ipv6hdr **ipv6hdr)
{
	struct ipv6hdr *ip6 = hc->pos;

	if (hc->pos + sizeof(struct ipv6hdr) > hc->data_end) {
		return -1;
	}

	hc->pos += sizeof(*ip6);
	*ipv6hdr = ip6;

	return ip6->nexthdr;
}

/* 
 * parses generic IP header and returns the version
 * this is useful in cases where packets don't have an Ethernet header
 */
static __always_inline int parse_geniphdr(struct hdr_cursor *hc, struct geniphdr **geniphdr)
{
	struct geniphdr *ip = hc->pos;

	if (hc->pos + sizeof(struct geniphdr) > hc->data_end) {
		return -1;
	}

	*geniphdr = ip;

	return ip->version >> 4; // IP version is in upper 4 bits
}

/* parses the UDP header and returns the data length */
static __always_inline int parse_udphdr(struct hdr_cursor *hc, struct udphdr **udphdr)
{
	struct udphdr *udp = hc->pos;

	if (hc->pos + sizeof(struct udphdr) > hc->data_end) {
		return -1;
	}

	hc->pos += sizeof(*udp);
	*udphdr = udp;

	return sizeof(*udp);
}

// Helper functions

static __always_inline int get_config_flags()
{
	__u32 key = 0;
	__u8 *v = bpf_map_lookup_elem(&config_map, &key);
	return v ? *v : 0;
}

static __always_inline int ipv4_allowed(__u32 saddr, __u32 daddr, struct metrics_value *mv)
{
	// Use hash map for exact IP matching (simpler and more efficient than LPM trie)
    // Convert to host-endian to match how loader stores keys
    __u32 src = bpf_ntohl(saddr);
    __u32 dst = bpf_ntohl(daddr);
	
	// Store lookup values for diagnostics
	if (mv) {
		mv->last_lookup_src_ne = saddr;
		mv->last_lookup_src_he = src;
		mv->last_lookup_dst_he = dst;
	}
	
	if (bpf_map_lookup_elem(&ipv4_cidr_map, &src))
		return 1;
	if (bpf_map_lookup_elem(&ipv4_cidr_map, &dst))
		return 1;
	// If neither source nor destination IP matches the configured targets, block this traffic
	// This ensures we only affect the specific container(s) configured in the attack
	return 0;
}

static __always_inline int ipv6_allowed(__u8 *saddr, __u8 *daddr)
{
	struct ipv6_lpm_key key;
	key.prefixlen = 128;
	__builtin_memcpy(key.addr, saddr, sizeof(key.addr));
	if (bpf_map_lookup_elem(&ipv6_cidr_map, &key))
		return 1;
	__builtin_memcpy(key.addr, daddr, sizeof(key.addr));
	if (bpf_map_lookup_elem(&ipv6_cidr_map, &key))
		return 1;
	// If neither source nor destination IP matches the configured targets, block this traffic
	// This ensures we only affect the specific container(s) configured in the attack
	return 0;
}

static __always_inline int port_allowed(__u16 port)
{
	__u8 *v = bpf_map_lookup_elem(&port_map, &port);
	return v ? *v : 1; // Allow all by default if no rules configured
}

static __always_inline int is_dns_query(struct hdr_cursor *hc)
{
	struct dns_header *dns = hc->pos;

	if (hc->pos + sizeof(struct dns_header) > hc->data_end) {
		return 0;
	}

	// Check if this is a DNS query (QR bit = 0)
	__u16 flags = bpf_ntohs(dns->flags);
	return (flags & 0x8000) == 0; // QR bit is 0 for queries
}

static __always_inline int inject_dns_error(struct __sk_buff *skb, __u32 eth_offset, __u32 ip_offset, __u32 udp_offset, __u32 dns_offset, int error_type, int is_ipv6)
{
	struct dns_header dns_hdr;

	// Read DNS header
	if (bpf_skb_load_bytes(skb, dns_offset, &dns_hdr, sizeof(dns_hdr)) < 0) {
		return 0;
	}

	// Convert query to response by setting QR bit
	__u16 flags = bpf_ntohs(dns_hdr.flags);
	flags |= 0x8000; // Set QR bit to 1 (response)

	// Set the appropriate error code
	if (error_type == DNS_RCODE_NXDOMAIN) {
		flags = (flags & 0xFFF0) | DNS_RCODE_NXDOMAIN;
	} else if (error_type == DNS_RCODE_SERVFAIL) {
		flags = (flags & 0xFFF0) | DNS_RCODE_SERVFAIL;
	}

	dns_hdr.flags = bpf_htons(flags);

	// Set response counts to 0 (no answers)
	dns_hdr.ancount = 0;
	dns_hdr.nscount = 0;
	dns_hdr.arcount = 0;

	// Ensure packet is writable
	if (bpf_skb_pull_data(skb, dns_offset + sizeof(dns_hdr)) < 0) {
		return 0;
	}

	// Write modified DNS header back
	if (bpf_skb_store_bytes(skb, dns_offset, &dns_hdr, sizeof(dns_hdr), BPF_F_RECOMPUTE_CSUM) < 0) {
		return 0;
	}

	// Now we need to swap IP addresses and UDP ports to send back to requester
	if (!is_ipv6) {
		// IPv4: swap src and dst addresses
		struct iphdr iph;
		if (bpf_skb_load_bytes(skb, ip_offset, &iph, sizeof(iph)) < 0) {
			return 0;
		}
		__u32 tmp_addr = iph.saddr;
		iph.saddr = iph.daddr;
		iph.daddr = tmp_addr;
		if (bpf_skb_store_bytes(skb, ip_offset, &iph, sizeof(iph), BPF_F_RECOMPUTE_CSUM) < 0) {
			return 0;
		}
	} else {
		// IPv6: swap src and dst addresses
		struct ipv6hdr ip6h;
		if (bpf_skb_load_bytes(skb, ip_offset, &ip6h, sizeof(ip6h)) < 0) {
			return 0;
		}
		struct in6_addr tmp_addr = ip6h.saddr;
		ip6h.saddr = ip6h.daddr;
		ip6h.daddr = tmp_addr;
		if (bpf_skb_store_bytes(skb, ip_offset, &ip6h, sizeof(ip6h), BPF_F_RECOMPUTE_CSUM) < 0) {
			return 0;
		}
	}

	// UDP: swap src and dst ports
	struct udphdr udph;
	if (bpf_skb_load_bytes(skb, udp_offset, &udph, sizeof(udph)) < 0) {
		return 0;
	}
	__u16 tmp_port = udph.source;
	udph.source = udph.dest;
	udph.dest = tmp_port;
	if (bpf_skb_store_bytes(skb, udp_offset, &udph, sizeof(udph), BPF_F_RECOMPUTE_CSUM) < 0) {
		return 0;
	}

	// If there's an Ethernet header, swap MAC addresses
	if (eth_offset < ip_offset) {
		struct ethhdr eth;
		if (bpf_skb_load_bytes(skb, eth_offset, &eth, sizeof(eth)) < 0) {
			return 1; // Continue even if MAC swap fails
		}
		unsigned char tmp_mac[6];
		__builtin_memcpy(tmp_mac, eth.h_source, 6);
		__builtin_memcpy(eth.h_source, eth.h_dest, 6);
		__builtin_memcpy(eth.h_dest, tmp_mac, 6);
		bpf_skb_store_bytes(skb, eth_offset, &eth, sizeof(eth), 0);
	}

	return 1;
}

// Main processing function
static __always_inline int process(struct __sk_buff *skb, int is_egress)
{
	struct hdr_cursor hc;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	struct geniphdr *geniph;
	int eth_proto, ip_proto;

	// Initialize header cursor
	hc.pos = (void *)(long)skb->data;
	hc.data_end = (void *)(long)skb->data_end;

	// Track offsets for inject_dns_error
	__u32 eth_offset = 0;
	__u32 ip_offset = 0;
	__u32 udp_offset = 0;

	// Update metrics
	__u32 mkey = 0;
	struct metrics_value *mv = bpf_map_lookup_elem(&metrics_map, &mkey);
	if (mv) {
		mv->seen++;
	}

	// Try to parse Ethernet header first
	eth_proto = parse_ethhdr(&hc, &eth);
	if (eth_proto >= 0) {
		ip_offset = sizeof(struct ethhdr);
	}

	// If Ethernet parsing failed, try generic IP header (for tun/raw interfaces)
	if (eth_proto < 0) {
		int ip_version = parse_geniphdr(&hc, &geniph);
		if (ip_version == 4) {
			eth_proto = bpf_htons(ETH_P_IP);
		} else if (ip_version == 6) {
			eth_proto = bpf_htons(ETH_P_IPV6);
		} else {
			return TC_ACT_OK;
		}
	}

	// Parse IP header
	if (eth_proto == bpf_htons(ETH_P_IP)) {
		if (mv)
			mv->ipv4++;

		ip_proto = parse_iphdr(&hc, &iph);
		if (ip_proto < 0)
			return TC_ACT_OK;

		if (ip_proto != IPPROTO_UDP)
			return TC_ACT_OK;

		// Calculate UDP offset (after IP header)
		udp_offset = ip_offset + ((__u32)iph->ihl * 4);

		// Parse UDP header
		if (parse_udphdr(&hc, &udph) < 0)
			return TC_ACT_OK;

		// Check if this is DNS traffic (port 53)
		__u16 sport = bpf_ntohs(udph->source);
		__u16 dport = bpf_ntohs(udph->dest);

		if (is_egress) {
			if (dport != 53)
				return TC_ACT_OK;
			if (mv)
				mv->egress_queries++;
		} else {
			if (sport != 53)
				return TC_ACT_OK;
			if (mv)
				mv->ingress_responses++;
		}

		// Check if this traffic is allowed based on IP/port filters
		if (mv) {
			mv->ipv4_allowed_called++;
			// Capture the last seen IPs for diagnostics (in network byte order)
			mv->last_saddr = iph->saddr;
			mv->last_daddr = iph->daddr;
		}
		if (!ipv4_allowed(iph->saddr, iph->daddr, mv)) {
			// Capture rejected IPs for diagnostics
			if (mv) {
				mv->last_rejected_saddr = iph->saddr;
				mv->last_rejected_daddr = iph->daddr;
			}
			return TC_ACT_OK;
		}
		if (mv)
			mv->ipv4_allowed_passed++;
		if (!port_allowed(sport) && !port_allowed(dport))
			return TC_ACT_OK;

		// For egress, check if this is a query
		if (is_egress) {
			if (!is_dns_query(&hc))
				return TC_ACT_OK;
		}

		if (mv)
			mv->dns_matched++;

		// Determine which error to inject
		int flags = get_config_flags();
		int error_type = DNS_RCODE_NXDOMAIN; // default

		if ((flags & CONFIG_RANDOM_CHOICE) && (flags & CONFIG_INJECT_NXDOMAIN) && (flags & CONFIG_INJECT_SERVFAIL)) {
			// Randomly choose between NXDOMAIN and SERVFAIL
			__u32 random = bpf_get_prandom_u32();
			error_type = (random % 2 == 0) ? DNS_RCODE_NXDOMAIN : DNS_RCODE_SERVFAIL;
		} else if (flags & CONFIG_INJECT_SERVFAIL) {
			error_type = DNS_RCODE_SERVFAIL;
		} else if (flags & CONFIG_INJECT_NXDOMAIN) {
			error_type = DNS_RCODE_NXDOMAIN;
		} else {
			return TC_ACT_OK; // No error injection configured
		}

		// Inject error on egress (queries from container)
		// We intercept the query and convert it to an error response immediately
		if (is_egress) {
			// Calculate DNS header offset (after UDP header)
			__u32 dns_offset = udp_offset + sizeof(struct udphdr);

			if (inject_dns_error(skb, eth_offset, ip_offset, udp_offset, dns_offset, error_type, 0)) {
				if (mv) {
					mv->injected++;
					if (error_type == DNS_RCODE_NXDOMAIN)
						mv->injected_nxdomain++;
					else if (error_type == DNS_RCODE_SERVFAIL)
						mv->injected_servfail++;
				}
				// Use bpf_redirect to send packet back to the same interface (ingress->egress)
				// skb->ifindex is the current interface (docker0)
				return bpf_redirect(skb->ifindex, 0);
			}
		}

	} else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
		if (mv)
			mv->ipv6++;

		ip_proto = parse_ipv6hdr(&hc, &ip6h);
		if (ip_proto < 0)
			return TC_ACT_OK;

		if (ip_proto != IPPROTO_UDP)
			return TC_ACT_OK;

		// Calculate UDP offset (after IPv6 header)
		udp_offset = ip_offset + sizeof(struct ipv6hdr);

		// Parse UDP header
		if (parse_udphdr(&hc, &udph) < 0)
			return TC_ACT_OK;

		// Check if this is DNS traffic (port 53)
		__u16 sport = bpf_ntohs(udph->source);
		__u16 dport = bpf_ntohs(udph->dest);

		if (is_egress) {
			if (dport != 53)
				return TC_ACT_OK;
			if (mv)
				mv->egress_queries++;
		} else {
			if (sport != 53)
				return TC_ACT_OK;
			if (mv)
				mv->ingress_responses++;
		}

		// Check if this traffic is allowed based on IP/port filters
		if (!ipv6_allowed(ip6h->saddr.in6_u.u6_addr8, ip6h->daddr.in6_u.u6_addr8))
			return TC_ACT_OK;
		if (!port_allowed(sport) && !port_allowed(dport))
			return TC_ACT_OK;

		// For egress, check if this is a query
		if (is_egress) {
			if (!is_dns_query(&hc))
				return TC_ACT_OK;
		}

		if (mv)
			mv->dns_matched++;

		// Determine which error to inject
		int flags = get_config_flags();
		int error_type = DNS_RCODE_NXDOMAIN; // default

		if ((flags & CONFIG_RANDOM_CHOICE) && (flags & CONFIG_INJECT_NXDOMAIN) && (flags & CONFIG_INJECT_SERVFAIL)) {
			__u32 random = bpf_get_prandom_u32();
			error_type = (random % 2 == 0) ? DNS_RCODE_NXDOMAIN : DNS_RCODE_SERVFAIL;
		} else if (flags & CONFIG_INJECT_SERVFAIL) {
			error_type = DNS_RCODE_SERVFAIL;
		} else if (flags & CONFIG_INJECT_NXDOMAIN) {
			error_type = DNS_RCODE_NXDOMAIN;
		} else {
			return TC_ACT_OK;
		}

		// Inject error on egress (queries from container)
		// We intercept the query and convert it to an error response immediately
		if (is_egress) {
			// Calculate DNS header offset (after UDP header)
			__u32 dns_offset = udp_offset + sizeof(struct udphdr);

			if (inject_dns_error(skb, eth_offset, ip_offset, udp_offset, dns_offset, error_type, 1)) {
				if (mv) {
					mv->injected++;
					if (error_type == DNS_RCODE_NXDOMAIN)
						mv->injected_nxdomain++;
					else if (error_type == DNS_RCODE_SERVFAIL)
						mv->injected_servfail++;
				}
				// Use bpf_redirect to send packet back to the same interface (ingress->egress)
				// skb->ifindex is the current interface (docker0)
				return bpf_redirect(skb->ifindex, 0);
			}
		}
	}

	return TC_ACT_OK;
}

SEC("tc/ingress")
int ingress_cls_func(struct __sk_buff *skb)
{
	// Directionality depends on mode:
	// - Container mode (docker0): ingress = traffic FROM containers (queries)
	// - Host mode (eth0/eno1): ingress = traffic TO host (responses)
	int flags = get_config_flags();
	int is_container_mode = (flags & CONFIG_IS_CONTAINER_MODE) != 0;
	
	if (is_container_mode) {
		// Ingress to docker0 = traffic FROM containers (queries going out)
		return process(skb, 1);  // is_egress=1 (container's perspective)
	} else {
		// Ingress to host interface = traffic TO host (responses coming in)
		return process(skb, 0);  // is_egress=0 (host's perspective)
	}
}

SEC("tc/egress")
int egress_cls_func(struct __sk_buff *skb)
{
	// Directionality depends on mode:
	// - Container mode (docker0): egress = traffic TO containers (responses)
	// - Host mode (eth0/eno1): egress = traffic FROM host (queries)
	int flags = get_config_flags();
	int is_container_mode = (flags & CONFIG_IS_CONTAINER_MODE) != 0;
	
	if (is_container_mode) {
		// Egress from docker0 = traffic TO containers (responses coming in)
		return process(skb, 0);  // is_egress=0 (container's perspective)
	} else {
		// Egress from host interface = traffic FROM host (queries going out)
		return process(skb, 1);  // is_egress=1 (host's perspective)
	}
}

char _license[] SEC("license") = "GPL";
