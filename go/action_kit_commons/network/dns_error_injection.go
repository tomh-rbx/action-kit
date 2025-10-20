// SPDX-License-Identifier: MIT
//go:build !windows

package network

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/network/ebpf"
	"github.com/steadybit/extension-kit/extutil"
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
	DNSErrorTypeTimeout  = "TIMEOUT"
)

// DNSErrorInjectionOpts injects DNS errors (NXDOMAIN/SERVFAIL) into DNS queries.
// Uses eBPF to intercept and modify DNS packets in real-time.
type DNSErrorInjectionOpts struct {
	Filter
	Interfaces  []string
	ErrorTypes  []string // NXDOMAIN, SERVFAIL, or BOTH
	ExecutionID string   // Execution ID for tracking the loader in the registry
	IsContainer bool     // true for container attacks (docker0), false for host attacks (eth0/eno1)
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

		// Close the loader
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
		DNSErrorTypeTimeout:  true,
	}

	for _, errorType := range o.ErrorTypes {
		if !validTypes[errorType] {
			return false, fmt.Errorf("invalid DNS error type: %s", errorType)
		}
	}

	// For DNS error injection, we need to be very specific about targeting
	// For container attacks, only use eBPF if we have specific container IPs to target
	if len(o.Include) == 0 {
		return false, fmt.Errorf("DNS error injection requires specific target IPs for safety")
	}

	// For container attacks, check for catch-all 0.0.0.0/0 or ::/0 which would affect all containers
	// For host attacks, catch-all ranges are allowed since they run in the host network namespace
	if o.IsContainer {
		for _, include := range o.Include {
			ipStr := include.Net.String()
			if ipStr == "0.0.0.0/0" || ipStr == "::/0" {
				return false, fmt.Errorf("DNS error injection cannot use catch-all IP ranges (0.0.0.0/0 or ::/0) for container attacks - specific container IPs must be configured")
			}
		}
	}

	// Convert our options to eBPF config
	config := ebpf.DNSErrorInjectionConfig{
		ErrorTypes:  o.ErrorTypes,
		Interfaces:  o.Interfaces,
		IsContainer: o.IsContainer,
	}

	// Extract container IP from includes - we'll add this to the shared loader
	var containerIP string
	for _, include := range o.Include {
		if include.Net.IP != nil {
			// Store the first IP as the container IP for this execution
			if containerIP == "" {
				containerIP = include.Net.IP.String()
			}
			config.IncludeCIDRs = append(config.IncludeCIDRs, include.Net.String())
		}
	}

	if containerIP == "" {
		return false, fmt.Errorf("no container IP found in includes")
	}

	// Port is always DNS port 53 (hardcoded in eBPF)

	// Ensure the embedded object is present on the host filesystem
	// We run eBPF on the host and target the container's network interface
	const ebpfObjectPath = "/etc/steadybit/dns_error_injection.o"
	if err := ebpf.WriteEmbeddedDNSErrorObject(ebpfObjectPath); err != nil {
		return false, fmt.Errorf("write eBPF object: %w", err)
	}

	// Create a dedicated loader for this execution
	loader, err := ebpf.NewDNSErrorInjectionLoader()
	if err != nil {
		return false, fmt.Errorf("create eBPF loader: %w", err)
	}

	// Try to load and attach eBPF program
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := loader.Load(ctx, config); err != nil {
		loader.Close()
		return false, fmt.Errorf("load eBPF program: %w", err)
	}

	// Store the loader in the global registry for cleanup when the experiment stops
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
	if o.IsContainer {
		sb.WriteString(", mode: container")
	} else {
		sb.WriteString(", mode: host")
	}
	sb.WriteString(")")
	writeStringForFilters(&sb, optimizeFilter(o.Filter))
	return sb.String()
}

// GetDNSErrorInjectionMessages retrieves metrics from the eBPF loader and formats them as markdown messages
func GetDNSErrorInjectionMessages(executionID string) (*[]action_kit_api.Message, error) {
	dnsLoaderRegistryLock.Lock()
	loader, exists := dnsLoaderRegistry[executionID]
	dnsLoaderRegistryLock.Unlock()

	if !exists {
		return nil, fmt.Errorf("no loader found for execution ID: %s", executionID)
	}

	// Get raw metrics from eBPF
	mv, err := loader.GetRawMetrics()
	if err != nil {
		return nil, err
	}

	log.Debug().
		Str("execution_id", executionID).
		Uint64("seen", mv.Seen).
		Uint64("dns_matched", mv.DNSMatched).
		Uint64("injected", mv.Injected).
		Msg("retrieved raw metrics from eBPF")

	// Format markdown content
	markdown := fmt.Sprintf(`### Packets Processed
- **Total Packets:** %d
- **DNS Requests Matched for Target:** %d

### Injections by Type
- **NXDOMAIN:** %d
- **SERVFAIL:** %d
- **TIMEOUT:** %d
- **Total Injected:** %d`,
		mv.Seen,
		mv.DNSMatched,
		mv.InjectedNXDOMAIN,
		mv.InjectedSERVFAIL,
		mv.InjectedTimeout,
		mv.Injected,
	)

	now := time.Now()
	messageType := "dns_stats_markdown"
	messages := []action_kit_api.Message{
		{
			Message:   markdown,
			Timestamp: &now,
			Type:      &messageType,
		},
	}

	return extutil.Ptr(messages), nil
}
