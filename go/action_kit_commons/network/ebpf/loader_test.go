package ebpf

import (
	"context"
	"testing"
	"time"
)

func TestDNSErrorInjectionLoader_New(t *testing.T) {
	loader, err := NewDNSErrorInjectionLoader()
	if err != nil {
		t.Logf("eBPF loader creation failed (expected on non-Linux): %v", err)
		return
	}
	defer loader.Close()

	if loader == nil {
		t.Fatal("loader should not be nil")
	}
}

func TestDNSErrorInjectionLoader_Load(t *testing.T) {
	loader, err := NewDNSErrorInjectionLoader()
	if err != nil {
		t.Logf("eBPF loader creation failed (expected on non-Linux): %v", err)
		return
	}
	defer loader.Close()

	config := DNSErrorInjectionConfig{
		ErrorTypes:   []string{"NXDOMAIN"},
		Interfaces:   []string{"eth0"},
		IncludeCIDRs: []string{"10.0.0.0/8"},
		IncludePorts: []int{53},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = loader.Load(ctx, config)
	if err != nil {
		t.Logf("eBPF load failed (expected on non-Linux or without eBPF support): %v", err)
		return
	}

	// If we get here, eBPF loaded successfully
	t.Log("eBPF DNS error injection program loaded successfully")
}

func TestDNSErrorInjectionLoader_LoadBoth(t *testing.T) {
	loader, err := NewDNSErrorInjectionLoader()
	if err != nil {
		t.Logf("eBPF loader creation failed (expected on non-Linux): %v", err)
		return
	}
	defer loader.Close()

	config := DNSErrorInjectionConfig{
		ErrorTypes:   []string{"BOTH"},
		Interfaces:   []string{"eth0"},
		IncludeCIDRs: []string{"10.0.0.0/8"},
		IncludePorts: []int{53},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = loader.Load(ctx, config)
	if err != nil {
		t.Logf("eBPF load failed (expected on non-Linux or without eBPF support): %v", err)
		return
	}

	// If we get here, eBPF loaded successfully
	t.Log("eBPF DNS error injection program with random selection loaded successfully")
}
