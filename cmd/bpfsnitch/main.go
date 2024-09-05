package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"github.com/nullswan/bpfsentinel/internal/bpf"
	bpfarch "github.com/nullswan/bpfsentinel/internal/bpf/arch"
	"github.com/nullswan/bpfsentinel/internal/kube"
	"github.com/nullswan/bpfsentinel/internal/logger"
	"github.com/nullswan/bpfsentinel/internal/metrics"
)

const (
	bpfProgramElf  = bpfarch.BpfProgramElf
	prometheusPort = 9090
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {


	flag.Parse()

	log := logger.Init()


	bpfCtx, err := bpf.Attach(
		log,
		bpfProgramElf,
	)
	if err != nil {
		return fmt.Errorf("failed while attaching bpf: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling to cancel context on termination.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		log.With("signal", <-sigChan).
			Info("Received signal, cancelling context")

		cancel()
		for _, kp := range bpfCtx.Kprobes {
			kp.Close()
		}

		bpfCtx.EventsReader.Close()
		log.Info("Closed event reader")
	}()

	metrics.RegisterMetrics()
	go metrics.StartServer(log, cancel, prometheusPort)

	syscallEventChan := make(chan *bpf.SyscallEvent)
	go consumeEvents(ctx, log, bpfCtx.EventsReader, syscallEventChan)

	for {
		select {
		case <-ctx.Done():
			log.Info("Context done, exiting")
			return nil
		case event := <-syscallEventChan:

			metrics.SyscallCounter.
				WithLabelValues(
					event.GetSyscallName(),
					fmt.Sprintf("%d", event.UserId),
					fmt.Sprintf("%d", event.CgroupId)).
				Inc()
		}
	}
}

func consumeEvents(
	ctx context.Context,
	log *slog.Logger,
	eventsReader *perf.Reader,
	syscallEventChan chan *bpf.SyscallEvent,
) {
	log.Info("Starting event reader")

	for {
		select {
		case <-ctx.Done():
			log.Info("Context done, stopping event reader")
			return
		default:
			record, err := eventsReader.Read()
			if err != nil {
				log.With("error", err).Error("Failed to read event")
				continue
			}

			if record.LostSamples > 0 {
				log.With("lost_samples", record.LostSamples).
					Warn("Lost samples")
				continue
			}

			event := (*bpf.SyscallEvent)(unsafe.Pointer(&record.RawSample[0]))
			syscallEventChan <- event
			log.With("syscall", event.GetSyscallName()).
				Debug("Received event")
		}
	}
}
