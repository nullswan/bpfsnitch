package bpf

import (
	"errors"
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
	tps := make([]link.Link, 0, len(bpfarch.WhitelistedSyscalls))
	for _, nbr := range bpfarch.WhitelistedSyscalls {
		syscallName := bpfarch.IdToSyscall[nbr]
		tp := TpMeta{
			family:  "syscalls",
			section: "tracepoint_sys_enter",
			name:    "sys_enter_" + syscallName,
		}

		logCtx := log.With(
			"family",
			tp.family,
			"section",
			tp.section,
			"name",
			tp.name,
		)

		tpLink, err := attachTracepoint(coll, tp)
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

		tps = append(tps, tpLink)
	}

	if len(tps) == 0 {
		return nil, errors.New("failed to attach any tracepoints")
	}

	log.Info("Attached tracepoints", "count", len(tps))

	return tps, nil
}

func attachTracepoint(
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
