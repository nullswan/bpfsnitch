package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"github.com/nullswan/bpfsnitch/internal/bpf"
	bpfarch "github.com/nullswan/bpfsnitch/internal/bpf/arch"
	"github.com/nullswan/bpfsnitch/internal/logger"
	"github.com/nullswan/bpfsnitch/internal/metrics"
	"github.com/nullswan/bpfsnitch/internal/workload"
	"github.com/nullswan/bpfsnitch/pkg/lru"
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
	var kubernetesMode bool
	flag.BoolVar(&kubernetesMode, "kubernetes", false, "Enable Kubernetes mode")

	flag.Parse()

	log := logger.Init()

	if kubernetesMode && !workload.IsSocketPresent() {
		return fmt.Errorf("runtime socket not found")
	}

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
		for _, kp := range bpfCtx.Tps {
			kp.Close()
		}

		bpfCtx.EventsReader.Close()
		log.Info("Closed event reader")
	}()

	metrics.RegisterMetrics()
	go metrics.StartServer(log, cancel, prometheusPort)

	syscallEventChan := make(chan *bpf.SyscallEvent)
	go consumeEvents(ctx, log, bpfCtx.EventsReader, syscallEventChan)

	shaResolver, err := workload.NewShaResolver()
	if err != nil {
		return fmt.Errorf("failed to create sha resolver: %w", err)
	}

	// TODO: LRU Cache
	bannedCgroupIds := make(map[uint64]struct{})

	pidToShaLRU := lru.New[uint64, string](1000)
	for {
		select {
		case <-ctx.Done():
			log.Info("Context done, exiting")
			return nil
		case event := <-syscallEventChan:
			if _, ok := bannedCgroupIds[event.CgroupId]; ok {
				continue
			}

			sha, ok := pidToShaLRU.Get(event.Pid)
			if !ok {
				fd, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", event.Pid))
				if err != nil {
					log.With("error", err).
						Error("Failed to open cgroup file")
					continue
				}
				defer fd.Close()

				content, err := io.ReadAll(fd)
				if err != nil {
					log.With("error", err).
						Error("Failed to read cgroup file")
					continue
				}

				contentStr := string(content)
				if !strings.Contains(contentStr, "k8s.io") {
					bannedCgroupIds[event.CgroupId] = struct{}{}
					continue
				}
				sha = contentStr[strings.LastIndex(contentStr, "/")+1:]

				// Prevent the last character from being a newline.
				sha = sha[0 : len(sha)-1]

				pidToShaLRU.Put(event.Pid, sha)
			}

			container, err := shaResolver.Resolve(sha)
			if err != nil {
				log.With("error", err).
					With("sha", sha).
					Error("Failed to resolve sha")

				continue
			}

			log.With("syscall", event.GetSyscallName()).
				With("pid", event.Pid).
				With("cgroup_id", event.CgroupId).
				With("container", container).
				Debug("Received event")

			metrics.SyscallCounter.
				WithLabelValues(
					event.GetSyscallName(),
					container,
				).
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