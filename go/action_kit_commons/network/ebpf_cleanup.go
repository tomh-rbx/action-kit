//go:build !windows

package network

import (
	"github.com/steadybit/action-kit/go/action_kit_commons/network/ebpf"
)

// CleanupOrphanedEBPFFilters removes any orphaned DNS error injection TC filters from previous crashes
// Should be called during extension initialization
func CleanupOrphanedEBPFFilters() error {
	return ebpf.CleanupOrphanedFilters()
}
