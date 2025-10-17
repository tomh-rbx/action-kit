// +build ignore

// SPDX-License-Identifier: MIT
// Packet parsing utilities - functions for parsing network packet headers
// SPDX-FileCopyrightText: 2025 Roblox Corporation
// Author: Tom Handal <thandal@roblox.com>

#include "packet_parse.h"

/**
 * parse_ethhdr - Parse Ethernet header and advance cursor
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *hc, struct ethhdr **ethhdr)
{
	struct ethhdr *eth = hc->pos;

	/* Check packet bounds */
	if (hc->pos + sizeof(struct ethhdr) > hc->data_end) {
		return -1;
	}

	hc->pos += sizeof(*eth);
	*ethhdr = eth;

	return eth->h_proto;
}

/**
 * parse_iphdr - Parse IPv4 header and advance cursor
 */
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

/**
 * parse_ipv6hdr - Parse IPv6 header and advance cursor
 */
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

/**
 * parse_geniphdr - Parse generic IP header to determine version
 * 
 * This is useful for interfaces without Ethernet headers (e.g., tun/raw).
 * The IP version is stored in the upper 4 bits of the first byte.
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

/**
 * parse_udphdr - Parse UDP header and advance cursor
 */
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

