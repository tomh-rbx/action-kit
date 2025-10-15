package ebpf

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	SteadybitDNSErrorMark = 0x1
	DnsPort               = 53
)

type DNSErrorInjectionConfig struct {
	ErrorTypes   []string
	IncludeCIDRs []string
	ExcludeCIDRs []string
	IncludePorts []int
	ExcludePorts []int
	Interfaces   []string
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
		}
	}

	if !hasNXDOMAIN && !hasSERVFAIL {
		return fmt.Errorf("no valid DNS error types configured")
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
	// Configure IPv4 CIDR map
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

			prefixLen, _ := ipNet.Mask.Size()
			key := struct {
				PrefixLen uint32
				Addr      uint32
			}{
				PrefixLen: uint32(prefixLen),
				Addr:      uint32(ipNet.IP.To4()[0])<<24 | uint32(ipNet.IP.To4()[1])<<16 | uint32(ipNet.IP.To4()[2])<<8 | uint32(ipNet.IP.To4()[3]),
			}

			value := uint8(1)
			if err := ipv4Map.Put(key, value); err != nil {
				log.Warn().Str("cidr", cidr).Err(err).Msg("failed to add IPv4 CIDR to map")
			}
		}
	}

	// Configure IPv6 CIDR map
	ipv6Map := l.coll.Maps["ipv6_cidr_map"]
	if ipv6Map != nil {
		for _, cidr := range config.IncludeCIDRs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Warn().Str("cidr", cidr).Err(err).Msg("invalid IPv6 CIDR, skipping")
				continue
			}

			if ipNet.IP.To4() != nil {
				continue // Skip IPv4 addresses
			}

			prefixLen, _ := ipNet.Mask.Size()
			key := struct {
				PrefixLen uint32
				Addr      [4]uint32
			}{
				PrefixLen: uint32(prefixLen),
			}

			// Convert IPv6 address to 4 uint32 values
			ipv6 := ipNet.IP.To16()
			for i := 0; i < 4; i++ {
				key.Addr[i] = uint32(ipv6[i*4])<<24 | uint32(ipv6[i*4+1])<<16 | uint32(ipv6[i*4+2])<<8 | uint32(ipv6[i*4+3])
			}

			value := uint8(1)
			if err := ipv6Map.Put(key, value); err != nil {
				log.Warn().Str("cidr", cidr).Err(err).Msg("failed to add IPv6 CIDR to map")
			}
		}
	}

	return nil
}

func (l *DNSErrorInjectionLoader) configurePortMaps(config DNSErrorInjectionConfig) error {
	portMap := l.coll.Maps["port_map"]
	if portMap == nil {
		return nil
	}

	// Add DNS port by default
	ports := []int{DnsPort}
	ports = append(ports, config.IncludePorts...)

	for _, port := range ports {
		key := uint16(port)
		value := uint8(1)
		if err := portMap.Put(key, value); err != nil {
			log.Warn().Int("port", port).Err(err).Msg("failed to add port to map")
		}
	}

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
		ingressFilter, err := attachTCFilter(link, ingressProg, "tc/ingress", netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			return fmt.Errorf("failed to attach ingress filter to %s: %w", ifaceName, err)
		}
		l.filters = append(l.filters, ingressFilter)

		// Attach egress filter
		egressFilter, err := attachTCFilter(link, egressProg, "tc/egress", netlink.HANDLE_MIN_EGRESS)
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
	Seen             uint64
	IPv4             uint64
	IPv6             uint64
	EgressQueries    uint64
	IngressResponses uint64
	DNSMatched       uint64
	Injected         uint64
	InjectedNXDOMAIN uint64
	InjectedSERVFAIL uint64
}

func (l *DNSErrorInjectionLoader) startMetricsLogger(interval time.Duration) {
	if l.coll == nil {
		return
	}
	metrics := l.coll.Maps["metrics_map"]
	if metrics == nil {
		return
	}
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
				return
			case <-ticker.C:
				// Reset local copy
				mv = metricsValue{}
				if err := metrics.Lookup(&key, &mv); err == nil {
					log.Info().
						Uint64("seen", mv.Seen).
						Uint64("ipv4", mv.IPv4).
						Uint64("ipv6", mv.IPv6).
						Uint64("egress_queries", mv.EgressQueries).
						Uint64("ingress_responses", mv.IngressResponses).
						Uint64("dns_matched", mv.DNSMatched).
						Uint64("injected", mv.Injected).
						Uint64("injected_nxdomain", mv.InjectedNXDOMAIN).
						Uint64("injected_servfail", mv.InjectedSERVFAIL).
						Msg("dns-error-injection metrics")
				}
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

// BuildEBPFObject compiles the eBPF C code to object file
func BuildDNSErrorInjectionObject() error {
	// Check if clang is available
	if _, err := exec.LookPath("clang"); err != nil {
		return fmt.Errorf("clang not found: %w", err)
	}

	// Compile eBPF C code
	cmd := exec.Command("clang",
		"-O2", "-g", "-target", "bpf",
		"-c", "dns_error_injection.c",
		"-o", "dns_error_injection.o")

	cmd.Dir = "action-kit/go/action_kit_commons/network/ebpf"

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("compile eBPF: %w, output: %s", err, string(output))
	}

	log.Info().Msg("eBPF DNS error injection object compiled successfully")
	return nil
}
