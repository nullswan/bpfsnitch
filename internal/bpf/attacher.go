package bpf

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	perfReaderBufSz = 1024
)

// Define a Kernel BPF context.
type KBContext struct {
	EventsReader *perf.Reader
	Tps          []link.Link
}

func Attach(
	log *slog.Logger,
	bpfProgramElf string,
) (*KBContext, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(bpfProgramElf)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF program: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF collection: %w", err)
	}
	defer coll.Close()

	log.Info("Loaded eBPF program", "programs", coll.Programs)
	log.Info("Loaded eBPF maps", "maps", coll.Maps)

	err = registerWhitelistedSyscalls(log, coll.Maps)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to register whitelisted syscalls: %w",
			err,
		)
	}

	syscallEventsReader, err := perf.NewReader(
		coll.Maps["syscall_events"],
		perfReaderBufSz,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create perf reader: %w", err)
	}

	tps, err := attachTracepoints(log, coll)
	if err != nil {
		return nil, fmt.Errorf("failed to attach tps: %w", err)
	}

	return &KBContext{
		EventsReader: syscallEventsReader,
		Tps:          tps,
	}, nil
}
