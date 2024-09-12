package bpf

import (
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	bpfarch "github.com/nullswan/bpfsnitch/internal/bpf/arch"
)

const (
	// Map name for the whitelist of syscalls.
	syscallsWhitelistMapName = "syscall_whitelist"
)

var ()

func registerWhitelistedSyscalls(
	log *slog.Logger,
	maps map[string]*ebpf.Map,
) error {
	syscallMap, ok := maps[syscallsWhitelistMapName]
	if !ok {
		return fmt.Errorf(
			"failed to find map %s",
			syscallsWhitelistMapName,
		)
	}

	for _, nbr := range bpfarch.WhitelistedSyscalls {
		syscallName := bpfarch.IdToSyscall[nbr]
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(nbr))

		placeholder := make([]byte, 4)
		if err := syscallMap.Update(
			buf,
			placeholder,
			ebpf.UpdateAny,
		); err != nil {
			return fmt.Errorf(
				"failed to update map %s: %w",
				syscallsWhitelistMapName,
				err,
			)
		}

		log.With("syscall_name", syscallName).Info("Registered syscall")
	}

	return nil
}
