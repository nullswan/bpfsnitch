package bpf

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	bpfarch "github.com/nullswan/bpfsnitch/internal/bpf/arch"
)

// Struct that holds bpf tracepoint required metadata
type TpMeta struct {
	family  string
	section string
	name    string
}

func attachTracepoints(
	log *slog.Logger,
	coll *ebpf.Collection,
) ([]link.Link, error) {
	kps := make([]link.Link, 0, len(bpfarch.WhitelistedSyscalls))
	for _, nbr := range bpfarch.WhitelistedSyscalls {
		syscallName := bpfarch.IdToSyscall[nbr]
		kp := TpMeta{
			family:  "syscalls",
			section: "tracepoint_sys_enter",
			name:    fmt.Sprintf("sys_enter_%s", syscallName),
		}

		logCtx := log.With(
			"family",
			kp.family,
			"section",
			kp.section,
			"name",
			kp.name,
		)

		kpLink, err := attachKProbe(coll, kp)
		if err != nil {
			logCtx.Error(
				"Failed to attach tracepoint",
				"error",
				err,
			)
			continue
		}

		logCtx.Info(
			"Attached tracepoint",
		)

		kps = append(kps, kpLink)
	}

	if len(kps) == 0 {
		return nil, fmt.Errorf("failed to attach any tracepoints")
	}

	log.Info("Attached tracepoints", "count", len(kps))

	return kps, nil
}

func attachKProbe(
	coll *ebpf.Collection,
	tp TpMeta,
) (link.Link, error) {
	prog := coll.Programs[tp.section]
	if prog == nil {
		return nil, fmt.Errorf("failed to find program %s", tp.section)
	}

	tpLink, err := link.Tracepoint(tp.family, tp.name, prog, nil)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to attach tracepoint %s: %w",
			tp.section,
			err,
		)
	}

	return tpLink, nil
}
