package bpf

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Define a Kernel BPF context.
type KBContext struct {
	SyscallRingBuffer *ringbuf.Reader
	NetworkRingBuffer *ringbuf.Reader

	Tps []link.Link
	Kps []link.Link
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

	syscallRingBuffer, err := ringbuf.NewReader(
		coll.Maps["syscall_events_rb"],
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ring buffer: %w", err)
	}

	networkRingBuffer, err := ringbuf.NewReader(
		coll.Maps["network_events_rb"],
	)
	if err != nil {
		err2 := syscallRingBuffer.Close()

		if err2 != nil {
			log.With("error", err2).
				Error("Failed to close ring buffer")
		}

		return nil, fmt.Errorf("failed to create ring buffer: %w", err)
	}

	tps, err := attachTracepoints(log, coll)
	if err != nil {
		err2 := syscallRingBuffer.Close()
		if err2 != nil {
			log.With("error", err2).
				Error("Failed to close perf reader")
		}

		err2 = networkRingBuffer.Close()
		if err2 != nil {
			log.With("error", err2).
				Error("Failed to close perf reader")
		}

		return nil, fmt.Errorf("failed to attach tps: %w", err)
	}

	kps, err := attachKProbes(log, coll)
	if err != nil {
		err2 := syscallRingBuffer.Close()
		if err2 != nil {
			log.With("error", err2).
				Error("Failed to close perf reader")
		}

		err2 = networkRingBuffer.Close()
		if err2 != nil {
			log.With("error", err2).
				Error("Failed to close perf reader")
		}

		for _, tp := range tps {
			tp.Close()
		}

		return nil, fmt.Errorf("failed to attach kps: %w", err)
	}

	return &KBContext{
		SyscallRingBuffer: syscallRingBuffer,
		NetworkRingBuffer: networkRingBuffer,
		Tps:               tps,
		Kps:               kps,
	}, nil
}
