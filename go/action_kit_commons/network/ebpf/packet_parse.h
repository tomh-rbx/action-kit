// SPDX-License-Identifier: MIT
// Packet parsing header - utility functions for parsing network packet headers
// SPDX-FileCopyrightText: 2025 Roblox Corporation
// Author: Tom Handal <thandal@roblox.com>

#ifndef __PACKET_PARSE_H__
#define __PACKET_PARSE_H__

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

// Header cursor structure for parsing
struct hdr_cursor {
	void *pos;
	void *data_end;
};

// Generic IP header for determining IP version
struct geniphdr {
	__u8 version;
};

/**
 * parse_ethhdr - Parse Ethernet header
 * @hc: Header cursor containing packet position
 * @ethhdr: Pointer to store the parsed Ethernet header
 *
 * Returns: Next protocol (eth->h_proto) on success, -1 on error
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *hc, struct ethhdr **ethhdr);

/**
 * parse_iphdr - Parse IPv4 header
 * @hc: Header cursor containing packet position
 * @iphdr: Pointer to store the parsed IPv4 header
 *
 * Returns: Next protocol (ip->protocol) on success, -1 on error
 */
static __always_inline int parse_iphdr(struct hdr_cursor *hc, struct iphdr **iphdr);

/**
 * parse_ipv6hdr - Parse IPv6 header
 * @hc: Header cursor containing packet position
 * @ipv6hdr: Pointer to store the parsed IPv6 header
 *
 * Returns: Next protocol (ip6->nexthdr) on success, -1 on error
 */
static __always_inline int parse_ipv6hdr(struct hdr_cursor *hc, struct ipv6hdr **ipv6hdr);

/**
 * parse_geniphdr - Parse generic IP header to determine version
 * @hc: Header cursor containing packet position
 * @geniphdr: Pointer to store the parsed generic IP header
 *
 * This is useful for interfaces without Ethernet headers (e.g., tun/raw).
 * Returns: IP version (4 or 6) on success, -1 on error
 */
static __always_inline int parse_geniphdr(struct hdr_cursor *hc, struct geniphdr **geniphdr);

/**
 * parse_udphdr - Parse UDP header
 * @hc: Header cursor containing packet position
 * @udphdr: Pointer to store the parsed UDP header
 *
 * Returns: UDP header size on success, -1 on error
 */
static __always_inline int parse_udphdr(struct hdr_cursor *hc, struct udphdr **udphdr);

#endif /* __PACKET_PARSE_H__ */
