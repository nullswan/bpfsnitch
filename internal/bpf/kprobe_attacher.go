package bpf

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Struct that holds bpf kprobe required metadata
type KProbeMeta struct {
	function string
	section  string
}

// List of kprobes that we want to attach to the kernel
var kpsMeta = []KProbeMeta{
	{
		function: "syscall_trace_enter",
		section:  "kprobe_syscall_trace_enter",
	},
}

func attachKProbes(
	log *slog.Logger,
	coll *ebpf.Collection,
) ([]link.Link, error) {
	kps := make([]link.Link, 0, len(kpsMeta))
	for _, kp := range kpsMeta {
		kpLink, err := attachKProbe(coll, kp, log)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to attach kprobe %s: %w",
				kp.section,
				err,
			)
		}

		kps = append(kps, kpLink)
	}

	return kps, nil
}

func attachKProbe(
	coll *ebpf.Collection,
	kp KProbeMeta,
	log *slog.Logger,
) (link.Link, error) {
	prog := coll.Programs[kp.section]
	if prog == nil {
		return nil, fmt.Errorf("failed to find program %s", kp.section)
	}

	kpLink, err := link.Kprobe(kp.function, prog, nil)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to attach kprobe %s: %w",
			kp.function,
			err,
		)
	}

	log.Info("Attached kprobe", "section", kp.section, "function", kp.function)

	return kpLink, nil
}
