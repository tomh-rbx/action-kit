// SPDX-License-Identifier: MIT
//go:build !windows

package network

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/steadybit/action-kit/go/action_kit_commons/network/ebpf"
)

// Global registry to track eBPF loaders by execution ID
// This is needed because the loader is not serialized with the action state
var (
	dnsLoaderRegistry     = make(map[string]*ebpf.DNSErrorInjectionLoader)
	dnsLoaderRegistryLock sync.Mutex
)

// DNS error types
const (
	DNSErrorTypeNXDOMAIN = "NXDOMAIN"
	DNSErrorTypeSERVFAIL = "SERVFAIL"
	DNSErrorTypeBoth     = "BOTH"
)

// DNSErrorInjectionOpts injects DNS errors (NXDOMAIN/SERVFAIL) into DNS queries.
// Uses eBPF to intercept and modify DNS packets in real-time.
type DNSErrorInjectionOpts struct {
	Filter
	Interfaces  []string
	ErrorTypes  []string // NXDOMAIN, SERVFAIL, or BOTH
	ExecutionID string   // Execution ID for tracking the loader in the registry
}

func (o *DNSErrorInjectionOpts) IpCommands(_ Family, _ Mode) ([]string, error) {
	// DNS error injection uses eBPF for packet modification
	// iptables is used only for marking packets, not for the actual error injection
	return nil, nil
}

func (o *DNSErrorInjectionOpts) TcCommands(mode Mode) ([]string, error) {
	// NOTE: We now use netlink for direct attachment, so this returns empty commands.
	// The actual attachment happens in TryEBPF() via the netlink library in the eBPF loader.
	// This prevents duplicate filter attachment (both netlink and tc commands).

	// On ModeDelete, clean up the eBPF loader from the registry
	if mode == ModeDelete && o.ExecutionID != "" {
		dnsLoaderRegistryLock.Lock()
		loader, exists := dnsLoaderRegistry[o.ExecutionID]
		if exists {
			delete(dnsLoaderRegistry, o.ExecutionID)
		}
		dnsLoaderRegistryLock.Unlock()

		if loader != nil {
			if err := loader.Close(); err != nil {
				return []string{}, fmt.Errorf("failed to cleanup eBPF loader: %w", err)
			}
		}
	}

	return []string{}, nil
}

// NftablesScript: not used for DNS error injection. We rely on eBPF for packet modification.
func (o *DNSErrorInjectionOpts) NftablesScript(_ Mode) (string, error) {
	return "", nil
}

// TryEBPF attempts to use eBPF for DNS error injection, returns true if successful
func (o *DNSErrorInjectionOpts) TryEBPF() (bool, error) {
	// Check if we have valid configuration for eBPF
	if len(o.ErrorTypes) == 0 {
		return false, fmt.Errorf("no DNS error types configured")
	}

	// Validate error types
	validTypes := map[string]bool{
		DNSErrorTypeNXDOMAIN: true,
		DNSErrorTypeSERVFAIL: true,
		DNSErrorTypeBoth:     true,
	}

	for _, errorType := range o.ErrorTypes {
		if !validTypes[errorType] {
			return false, fmt.Errorf("invalid DNS error type: %s", errorType)
		}
	}

	// For DNS error injection, we need to be very specific about targeting
	// Only use eBPF if we have specific container IPs to target
	if len(o.Include) == 0 {
		return false, fmt.Errorf("DNS error injection requires specific target IPs for safety")
	}

	// Create eBPF loader
	loader, err := ebpf.NewDNSErrorInjectionLoader()
	if err != nil {
		return false, fmt.Errorf("create eBPF loader: %w", err)
	}

	// Convert our options to eBPF config
	config := ebpf.DNSErrorInjectionConfig{
		ErrorTypes: o.ErrorTypes,
		Interfaces: o.Interfaces,
	}

	// Add include CIDRs - these should be the specific container IPs
	for _, include := range o.Include {
		if include.Net.IP != nil {
			config.IncludeCIDRs = append(config.IncludeCIDRs, include.Net.String())
		}
	}

	// Add include ports - only DNS port
	for _, include := range o.Include {
		if include.PortRange.From != 0 {
			config.IncludePorts = append(config.IncludePorts, int(include.PortRange.From))
		}
	}

	// Ensure the embedded object is present on the host filesystem
	// We run eBPF on the host and target the container's network interface
	const ebpfObjectPath = "/etc/steadybit/dns_error_injection.o"
	if err := ebpf.WriteEmbeddedDNSErrorObject(ebpfObjectPath); err != nil {
		return false, fmt.Errorf("write eBPF object: %w", err)
	}

	// Try to load and attach eBPF program
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := loader.Load(ctx, config); err != nil {
		loader.Close()
		return false, fmt.Errorf("load eBPF program: %w", err)
	}

	// Store the loader in the global registry for cleanup when the experiment stops
	// The ExecutionID is used as the key to retrieve the loader during cleanup
	// TcCommands(ModeDelete) will look up the loader by ExecutionID and call Close()
	if o.ExecutionID != "" {
		dnsLoaderRegistryLock.Lock()
		dnsLoaderRegistry[o.ExecutionID] = loader
		dnsLoaderRegistryLock.Unlock()
	}

	return true, nil
}

// ValidateTargeting ensures we have specific container targets for safety
func (o *DNSErrorInjectionOpts) ValidateTargeting() error {
	if len(o.Include) == 0 {
		return fmt.Errorf("DNS error injection requires specific target IPs for safety - cannot affect all DNS traffic")
	}

	// Check if we have any IP targets
	hasIPTargets := false
	for _, include := range o.Include {
		if include.Net.IP != nil {
			hasIPTargets = true
			break
		}
	}

	if !hasIPTargets {
		return fmt.Errorf("DNS error injection requires specific target IP addresses for safety")
	}

	return nil
}

func (o *DNSErrorInjectionOpts) String() string {
	var sb strings.Builder
	sb.WriteString("injecting DNS errors: ")
	sb.WriteString(strings.Join(o.ErrorTypes, ", "))
	sb.WriteString(" (interfaces: ")
	sb.WriteString(strings.Join(o.Interfaces, ", "))
	sb.WriteString(")")
	writeStringForFilters(&sb, optimizeFilter(o.Filter))
	return sb.String()
}
