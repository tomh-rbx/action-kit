// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Roblox Corporation
// Author: Tom Handal <thandal@roblox.com>

//go:build linux

package ebpf

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
)

//go:embed dns_error_injection.o
var dnsErrorInjectionObject []byte

const (
	ConfigInjectNXDOMAIN  = 0x01
	ConfigInjectSERVFAIL  = 0x02
	ConfigRandomChoice    = 0x04
	ConfigIsContainerMode = 0x08
	ConfigInjectTimeout   = 0x10
	SteadybitDNSErrorMark = 0x1
	DnsPort               = 53
)

type DNSErrorInjectionConfig struct {
	ErrorTypes   []string
	IncludeCIDRs []string
	Interfaces   []string
	IsContainer  bool // true for container attacks (docker0), false for host attacks (eth0/eno1)
}

type DNSErrorInjectionLoader struct {
	spec        *ebpf.CollectionSpec
	coll        *ebpf.Collection
	links       []link.Link
	filters     []*netlink.BpfFilter // TC filters (separate from links)
	interfaces  []string
	metricsStop chan struct{}
	metricsDone chan struct{}
}

func NewDNSErrorInjectionLoader() (*DNSErrorInjectionLoader, error) {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	// Load embedded eBPF object
	log.Debug().Int("obj_len", len(dnsErrorInjectionObject)).Msg("ebpf: loading embedded DNS error injection object")
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(dnsErrorInjectionObject))
	if err != nil {
		return nil, fmt.Errorf("load eBPF spec: %w", err)
	}
	log.Debug().Int("programs", len(spec.Programs)).Int("maps", len(spec.Maps)).Msg("ebpf: DNS error injection collection spec loaded")

	return &DNSErrorInjectionLoader{
		spec: spec,
	}, nil
}

func (l *DNSErrorInjectionLoader) Load(ctx context.Context, config DNSErrorInjectionConfig) error {
	// Create collection
	coll, err := ebpf.NewCollection(l.spec)
	if err != nil {
		return fmt.Errorf("create eBPF collection: %w", err)
	}
	l.coll = coll

	// Configure maps
	if err := l.configureMaps(config); err != nil {
		return fmt.Errorf("configure maps: %w", err)
	}

	// Attach programs to network interfaces
	if err := l.attachPrograms(ctx, config.Interfaces); err != nil {
		return fmt.Errorf("attach programs: %w", err)
	}

	l.interfaces = config.Interfaces

	// Start periodic metrics logging
	l.startMetricsLogger(10 * time.Second)
	return nil
}

// Load creates the eBPF collection without attaching
func (l *DNSErrorInjectionLoader) LoadCollection() error {
	coll, err := ebpf.NewCollection(l.spec)
	if err != nil {
		return fmt.Errorf("create eBPF collection: %w", err)
	}
	l.coll = coll
	return nil
}

// Attach attaches the eBPF programs to network interfaces
func (l *DNSErrorInjectionLoader) Attach(config DNSErrorInjectionConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Attach programs to network interfaces
	if err := l.attachPrograms(ctx, config.Interfaces); err != nil {
		return fmt.Errorf("attach programs: %w", err)
	}

	l.interfaces = config.Interfaces

	// Start periodic metrics logging
	l.startMetricsLogger(10 * time.Second)
	return nil
}

func (l *DNSErrorInjectionLoader) configureMaps(config DNSErrorInjectionConfig) error {
	// Configure error types
	configFlags := uint8(0)
	hasNXDOMAIN := false
	hasSERVFAIL := false

	for _, errorType := range config.ErrorTypes {
		switch errorType {
		case "NXDOMAIN":
			configFlags |= ConfigInjectNXDOMAIN
			hasNXDOMAIN = true
		case "SERVFAIL":
			configFlags |= ConfigInjectSERVFAIL
			hasSERVFAIL = true
		case "BOTH":
			configFlags |= ConfigInjectNXDOMAIN | ConfigInjectSERVFAIL | ConfigRandomChoice
			hasNXDOMAIN = true
			hasSERVFAIL = true
		case "TIMEOUT":
			configFlags |= ConfigInjectTimeout
			// For timeout, we don't need NXDOMAIN or SERVFAIL, so we set a flag to skip the validation
			hasNXDOMAIN = true // Just to pass validation - timeout is a valid standalone option
		}
	}

	if !hasNXDOMAIN && !hasSERVFAIL {
		return fmt.Errorf("no valid DNS error types configured")
	}

	// Add container mode flag
	if config.IsContainer {
		configFlags |= ConfigIsContainerMode
	}

	// Set config flags
	configMap := l.coll.Maps["config_map"]
	if configMap != nil {
		key := uint32(0)
		if err := configMap.Put(key, configFlags); err != nil {
			return fmt.Errorf("set config flags: %w", err)
		}
	}

	// Configure CIDR maps
	if err := l.configureCIDRMaps(config); err != nil {
		return fmt.Errorf("configure CIDR maps: %w", err)
	}

	// Configure port maps
	if err := l.configurePortMaps(config); err != nil {
		return fmt.Errorf("configure port maps: %w", err)
	}

	return nil
}

func (l *DNSErrorInjectionLoader) configureCIDRMaps(config DNSErrorInjectionConfig) error {
	log.Info().Int("cidr_count", len(config.IncludeCIDRs)).Msg("configuring CIDR maps")

	// Configure IPv4 CIDR map (now using hash map for exact matching)
	ipv4Map := l.coll.Maps["ipv4_cidr_map"]
	if ipv4Map != nil {
		for _, cidr := range config.IncludeCIDRs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Warn().Str("cidr", cidr).Err(err).Msg("invalid IPv4 CIDR, skipping")
				continue
			}

			if ipNet.IP.To4() == nil {
				continue // Skip IPv6 addresses
			}

			// Store in the same byte order that bpf_ntohl will produce from network packets
			// bpf_ntohl converts network byte order (big-endian) to host byte order (little-endian on x86)
			// For IP 172.17.0.3 (0xAC110003 in network order), bpf_ntohl produces 0x031011AC
			ipBytes := ipNet.IP.To4()
			key := uint32(ipBytes[0])<<24 | uint32(ipBytes[1])<<16 | uint32(ipBytes[2])<<8 | uint32(ipBytes[3])

			value := uint8(1)
			if err := ipv4Map.Put(key, value); err != nil {
				log.Warn().Str("cidr", cidr).Err(err).Msg("failed to add IPv4 to map")
			} else {
				log.Info().
					Str("cidr", cidr).
					Uint32("addr_host_endian", key).
					Msg("added IPv4 (host-endian) to eBPF hash map")
			}
		}
	}

	// IPv6 support not yet implemented
	// Future: Add ipv6_cidr_map configuration here

	return nil
}

func (l *DNSErrorInjectionLoader) configurePortMaps(config DNSErrorInjectionConfig) error {
	portMap := l.coll.Maps["port_map"]
	if portMap == nil {
		return nil
	}

	// Always configure DNS port 53
	// Note: The eBPF code also hardcodes port 53 checks, so this map is somewhat redundant
	// but kept for consistency with the eBPF map structure
	key := uint16(DnsPort)
	value := uint8(1)
	if err := portMap.Put(key, value); err != nil {
		return fmt.Errorf("failed to configure DNS port: %w", err)
	}

	log.Debug().Int("port", DnsPort).Msg("configured DNS port")
	return nil
}

func (l *DNSErrorInjectionLoader) attachPrograms(ctx context.Context, interfaces []string) error {
	if len(interfaces) == 0 {
		return fmt.Errorf("no interfaces specified")
	}

	// Get ingress and egress programs
	ingressProg := l.coll.Programs["ingress_cls_func"]
	egressProg := l.coll.Programs["egress_cls_func"]

	if ingressProg == nil || egressProg == nil {
		return fmt.Errorf("required eBPF programs not found")
	}

	// Attach programs to each interface using netlink
	for _, ifaceName := range interfaces {
		// Get the network link by name
		link, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return fmt.Errorf("failed to get link %s: %w", ifaceName, err)
		}

		// Attach ingress filter
		ingressFilter, err := attachTCFilter(link, ingressProg, "steadybit-dns-error-injection/ingress", netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			return fmt.Errorf("failed to attach ingress filter to %s: %w", ifaceName, err)
		}
		l.filters = append(l.filters, ingressFilter)

		// Attach egress filter
		egressFilter, err := attachTCFilter(link, egressProg, "steadybit-dns-error-injection/egress", netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			return fmt.Errorf("failed to attach egress filter to %s: %w", ifaceName, err)
		}
		l.filters = append(l.filters, egressFilter)

		log.Info().
			Str("interface", ifaceName).
			Int("ifindex", link.Attrs().Index).
			Str("ingress_program", ingressProg.String()).
			Str("egress_program", egressProg.String()).
			Msg("DNS error injection programs attached via netlink")
	}

	return nil
}

// attachTCFilter attaches a TC filter to a network interface
func attachTCFilter(link netlink.Link, prog *ebpf.Program, progName string, qdiscParent uint32) (*netlink.BpfFilter, error) {
	// Ensure clsact qdisc exists
	if err := replaceQdisc(link); err != nil {
		return nil, fmt.Errorf("replacing clsact qdisc for interface %s: %w", link.Attrs().Name, err)
	}

	// Create the BPF filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    qdiscParent,
			Handle:    1,
			Protocol:  0x0003, // ETH_P_ALL - Capture all protocols
			Priority:  1,
		},
		Fd:           prog.FD(),
		Name:         fmt.Sprintf("%s-%s", progName, link.Attrs().Name),
		DirectAction: true,
	}

	// Replace any existing filter
	if err := netlink.FilterReplace(filter); err != nil {
		return nil, fmt.Errorf("replacing tc filter: %w", err)
	}

	return filter, nil
}

// replaceQdisc ensures a clsact qdisc exists on the interface
func replaceQdisc(link netlink.Link) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	return netlink.QdiscReplace(qdisc)
}

func (l *DNSErrorInjectionLoader) Close() error {
	var errs []error

	// Stop metrics logger
	if l.metricsStop != nil {
		close(l.metricsStop)
		<-l.metricsDone
		l.metricsStop = nil
		l.metricsDone = nil
	}

	// Delete all TC filters
	for _, filter := range l.filters {
		if err := netlink.FilterDel(filter); err != nil {
			errs = append(errs, fmt.Errorf("delete filter: %w", err))
		}
	}

	// Close all links
	for _, link := range l.links {
		if err := link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close link: %w", err))
		}
	}

	// Close collection
	if l.coll != nil {
		l.coll.Close()
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during cleanup: %v", errs)
	}

	return nil
}

type metricsValue struct {
	Seen             uint64 // Total packets seen
	IPv4             uint64 // IPv4 packets
	IPv6             uint64 // IPv6 packets (future use)
	DNSMatched       uint64 // DNS packets matching our filters
	Injected         uint64 // Total DNS errors injected
	InjectedNXDOMAIN uint64 // NXDOMAIN errors injected
	InjectedSERVFAIL uint64 // SERVFAIL errors injected
	InjectedTimeout  uint64 // TIMEOUT (dropped packets)
	LastSaddr        uint32 // Last seen source IP (for debugging)
	LastDaddr        uint32 // Last seen dest IP (for debugging)
}

func (l *DNSErrorInjectionLoader) startMetricsLogger(interval time.Duration) {
	if l.coll == nil {
		log.Warn().Msg("metrics logger: coll is nil, not starting")
		return
	}
	metrics := l.coll.Maps["metrics_map"]
	if metrics == nil {
		log.Warn().Msg("metrics logger: metrics_map not found, not starting")
		return
	}
	log.Info().Dur("interval", interval).Msg("starting DNS error injection metrics logger")
	l.metricsStop = make(chan struct{})
	l.metricsDone = make(chan struct{})
	go func() {
		defer close(l.metricsDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		key := uint32(0)
		var mv metricsValue
		for {
			select {
			case <-l.metricsStop:
				log.Info().Msg("metrics logger stopped")
				return
			case <-ticker.C:
				// Reset local copy
				mv = metricsValue{}
				if err := metrics.Lookup(&key, &mv); err != nil {
					log.Debug().Err(err).Msg("metrics lookup failed - eBPF program may not be executing")
					continue
				}

				// Convert IPs from network byte order to strings for logging
				formatIP := func(ip uint32) string {
					return fmt.Sprintf("%d.%d.%d.%d",
						byte(ip&0xff),
						byte((ip>>8)&0xff),
						byte((ip>>16)&0xff),
						byte((ip>>24)&0xff))
				}

				logEvent := log.Info().
					Uint64("seen", mv.Seen).
					Uint64("ipv4", mv.IPv4).
					Uint64("ipv6", mv.IPv6).
					Uint64("dns_matched", mv.DNSMatched).
					Uint64("injected", mv.Injected).
					Uint64("injected_nxdomain", mv.InjectedNXDOMAIN).
					Uint64("injected_servfail", mv.InjectedSERVFAIL).
					Uint64("injected_timeout", mv.InjectedTimeout)

				if mv.LastSaddr != 0 || mv.LastDaddr != 0 {
					logEvent = logEvent.
						Str("last_saddr", formatIP(mv.LastSaddr)).
						Str("last_daddr", formatIP(mv.LastDaddr))
				}

				logEvent.Msg("dns-error-injection metrics")
			}
		}
	}()
}

// WriteEmbeddedDNSErrorObject writes the embedded dns_error_injection.o to the given absolute path.
// Creates parent directories as needed with 0755 and writes the file with 0644 permissions.
func WriteEmbeddedDNSErrorObject(targetPath string) error {
	if targetPath == "" {
		return fmt.Errorf("targetPath must not be empty")
	}
	if !filepath.IsAbs(targetPath) {
		return fmt.Errorf("targetPath must be absolute: %s", targetPath)
	}
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}
	if err := os.WriteFile(targetPath, dnsErrorInjectionObject, 0o644); err != nil {
		return fmt.Errorf("write eBPF object to %s failed: %w", targetPath, err)
	}
	log.Debug().Str("path", targetPath).Int("size", len(dnsErrorInjectionObject)).Msg("wrote embedded DNS eBPF object")
	return nil
}

// CleanupOrphanedFilters removes any orphaned DNS error injection TC filters from previous crashes
// Should be called during extension initialization
func CleanupOrphanedFilters() error {
	log.Info().Msg("checking for orphaned DNS error injection TC filters from previous crashes")

	// Get all network interfaces
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list network links: %w", err)
	}

	cleanedCount := 0
	for _, link := range links {
		// Check common interfaces where we attach eBPF programs
		ifName := link.Attrs().Name
		if ifName != "docker0" && !strings.HasPrefix(ifName, "br-") &&
			ifName != "eth0" && !strings.HasPrefix(ifName, "eno") {
			continue // Skip interfaces we don't use
		}

		// Check for our TC filters on both ingress and egress
		for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
			filters, err := netlink.FilterList(link, parent)
			if err != nil {
				log.Warn().
					Str("interface", ifName).
					Uint32("parent", parent).
					Err(err).
					Msg("failed to list TC filters")
				continue
			}

			for _, filter := range filters {
				bpfFilter, ok := filter.(*netlink.BpfFilter)
				if !ok {
					continue
				}

				// Check if this is our DNS error injection filter
				// Our filters have very specific names that include "steadybit-dns-error-injection"
				// This makes them uniquely identifiable as our filters
				expectedIngressName := fmt.Sprintf("steadybit-dns-error-injection/ingress-%s", ifName)
				expectedEgressName := fmt.Sprintf("steadybit-dns-error-injection/egress-%s", ifName)

				if bpfFilter.Name == expectedIngressName || bpfFilter.Name == expectedEgressName {
					log.Warn().
						Str("interface", ifName).
						Str("filter_name", bpfFilter.Name).
						Uint32("handle", bpfFilter.Handle).
						Uint32("priority", uint32(bpfFilter.Priority)).
						Msg("removing orphaned DNS error injection TC filter")

					if err := netlink.FilterDel(bpfFilter); err != nil {
						log.Warn().
							Str("interface", ifName).
							Err(err).
							Msg("failed to delete orphaned TC filter")
					} else {
						cleanedCount++
					}
				}
			}
		}
	}

	if cleanedCount > 0 {
		log.Info().Int("count", cleanedCount).Msg("cleaned up orphaned DNS error injection TC filters")
	} else {
		log.Info().Msg("no orphaned DNS error injection TC filters found")
	}

	return nil
}

// GetRawMetrics retrieves raw metrics from the eBPF program
func (l *DNSErrorInjectionLoader) GetRawMetrics() (*metricsValue, error) {
	if l.coll == nil {
		return nil, fmt.Errorf("eBPF collection not loaded")
	}

	// Get the metrics map
	metricsMap := l.coll.Maps["metrics_map"]
	if metricsMap == nil {
		return nil, fmt.Errorf("metrics map not found in eBPF collection")
	}

	// Read metrics from the eBPF map
	var key uint32 = 0
	var mv metricsValue
	if err := metricsMap.Lookup(&key, &mv); err != nil {
		return nil, fmt.Errorf("failed to read metrics from eBPF map: %w", err)
	}

	return &mv, nil
}
