package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/nullswan/bpfsnitch/internal/bpf"
	bpfarch "github.com/nullswan/bpfsnitch/internal/bpf/arch"
	"github.com/nullswan/bpfsnitch/internal/kernel"
	"github.com/nullswan/bpfsnitch/internal/metrics"
	"github.com/nullswan/bpfsnitch/internal/profile"
	"github.com/nullswan/bpfsnitch/internal/sig"
	"github.com/nullswan/bpfsnitch/internal/workload"
	"github.com/nullswan/bpfsnitch/pkg/lru"
)

const (
	bpfProgramElf         = bpfarch.BpfProgramElf
	cacheBannedSz         = 1000
	cachePidToShaSz       = 1000
	defaultPrometheusPort = 9090
	minKernelVersion      = "5.8"
)

func Run(
	log *slog.Logger,
) error {
	kernelVersion, err := kernel.GetKernelVersion()
	if err != nil {
		return fmt.Errorf("failed to get kernel version: %w", err)
	}

	if kernel.CompareVersions(kernelVersion, minKernelVersion) < 0 {
		return fmt.Errorf(
			"kernel version %s is not supported, minimum is %s",
			kernelVersion,
			minKernelVersion,
		)
	}

	var kubernetesMode bool
	flag.BoolVar(&kubernetesMode, "kubernetes", false, "Enable Kubernetes mode")

	var enablePprof bool
	flag.BoolVar(&enablePprof, "pprof", false, "Enable pprof")

	var enableProfiling bool
	flag.BoolVar(&enableProfiling, "profiling", false, "Enable profiling")

	var prometheusPort uint64
	flag.Uint64Var(
		&prometheusPort,
		"prometheus-port",
		defaultPrometheusPort,
		"Prometheus port",
	)

	flag.Parse()

	if enableProfiling {
		log.Info("Profiling enabled")
		err := profile.SetupProfiling(log)
		if err != nil {
			return fmt.Errorf("failed to setup profiling: %w", err)
		}
	}

	if kubernetesMode {
		if !workload.IsSocketPresent() {
			return errors.New("runtime socket not found")
		}
		log.Info("Kubernetes mode enabled")
	}

	bpfCtx, err := bpf.Attach(log, bpfProgramElf)
	if err != nil {
		return fmt.Errorf("failed while attaching bpf: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling to cancel context on termination.
	sig.SetupHandler(cancel, bpfCtx, log)

	metrics.RegisterMetrics()
	if enablePprof {
		log.Info("pprof enabled")
		profile.SetupPprof()
	}

	go metrics.StartServer(log, cancel, prometheusPort)

	syscallEventChan := make(chan *bpf.SyscallEvent)
	networkEventChan := make(chan *bpf.NetworkEvent)
	go bpf.ConsumeEvents(ctx, log, bpfCtx.SyscallRingBuffer, syscallEventChan)
	go bpf.ConsumeEvents(ctx, log, bpfCtx.NetworkRingBuffer, networkEventChan)

	var shaResolver *workload.ShaResolver
	if kubernetesMode {
		shaResolver, err = workload.NewShaResolver()
		if err != nil {
			return fmt.Errorf("failed to create sha resolver: %w", err)
		}
	}

	bannedCgroupIDs := lru.New[uint64, struct{}](cacheBannedSz)
	pidToShaLRU := lru.New[uint64, string](cachePidToShaSz)

	procPath := "/proc"
	if kubernetesMode {
		procPath = "/host_proc"
	}
	log.
		With("proc_path", procPath).
		With("kubernetes_mode", kubernetesMode).
		Info("Starting event processor")

	for {
		select {
		case <-ctx.Done():
			log.Info("Context done, exiting")
			return nil
		case event := <-networkEventChan:
			if !kubernetesMode {
				continue
			}
			pod, err := workload.ResolvePod(
				event.Pid,
				event.CgroupID,
				pidToShaLRU,
				bannedCgroupIDs,
				shaResolver,
				procPath,
				log,
			)
			if err != nil {
				if !errors.Is(err, workload.ErrCgroupIDBanned) {
					log.With("error", err).Debug("failed to resolve pod")
				}
				continue
			}

			bpf.ProcessNetworkEvent(event, pod, log)
		case event := <-syscallEventChan:
			if kubernetesMode {
				pod, err := workload.ResolvePod(
					event.Pid,
					event.CgroupID,
					pidToShaLRU,
					bannedCgroupIDs,
					shaResolver,
					procPath,
					log,
				)
				if err != nil {
					if !errors.Is(err, workload.ErrCgroupIDBanned) {
						log.With("error", err).
							Debug("failed to resolve pod")
					}
					continue
				}

				bpf.ProcessSyscallEvent(event, pod, log)
			} else {
				bpf.ProcessSyscallEvent(event, strconv.FormatUint(event.Pid, 10), log)
			}
		}
	}
}
