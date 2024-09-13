package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/nullswan/bpfsnitch/internal/bpf"
	bpfarch "github.com/nullswan/bpfsnitch/internal/bpf/arch"
	"github.com/nullswan/bpfsnitch/internal/logger"
	"github.com/nullswan/bpfsnitch/internal/metrics"
	"github.com/nullswan/bpfsnitch/internal/workload"
	"github.com/nullswan/bpfsnitch/pkg/lru"
)

const (
	bpfProgramElf   = bpfarch.BpfProgramElf
	prometheusPort  = 9090
	cacheBannedSz   = 1000
	cachePidToShaSz = 1000
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var kubernetesMode bool
	flag.BoolVar(&kubernetesMode, "kubernetes", false, "Enable Kubernetes mode")

	var enablePprof bool
	flag.BoolVar(&enablePprof, "pprof", false, "Enable pprof")

	flag.Parse()

	log := logger.Init()

	if kubernetesMode && !workload.IsSocketPresent() {
		return errors.New("runtime socket not found")
	} else if kubernetesMode {
		log.Info("Kubernetes mode enabled")
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
		for _, tp := range bpfCtx.Tps {
			tp.Close()
		}

		for _, kp := range bpfCtx.Kps {
			kp.Close()
		}

		bpfCtx.SyscallEventReader.Close()
		bpfCtx.NetworkEventReader.Close()

		log.Info("Closed event reader")
	}()

	metrics.RegisterMetrics()
	if enablePprof {
		log.Info("pprof enabled")
		http.HandleFunc("/debug/pprof/", pprof.Index)
		http.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		http.HandleFunc("/debug/pprof/profile", pprof.Profile)
		http.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		http.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	go metrics.StartServer(log, cancel, prometheusPort)

	syscallEventChan := make(chan *bpf.SyscallEvent)
	networkEventChan := make(chan *bpf.NetworkEvent)
	go bpf.ConsumeEvents(ctx, log, bpfCtx.SyscallEventReader, syscallEventChan)
	go bpf.ConsumeEvents(ctx, log, bpfCtx.NetworkEventReader, networkEventChan)

	var shaResolver *workload.ShaResolver
	if kubernetesMode {
		shaResolver, err = workload.NewShaResolver()
		if err != nil {
			return fmt.Errorf("failed to create sha resolver: %w", err)
		}
	}

	bannedCgroupIDs := lru.New[uint64, struct{}](cacheBannedSz)
	pidToShaLRU := lru.New[uint64, string](cachePidToShaSz)
	for {
		select {
		case <-ctx.Done():
			log.Info("Context done, exiting")
			return nil
		case event := <-networkEventChan:
			if !kubernetesMode {
				continue
			}

			sha, ok := pidToShaLRU.Get(event.Pid)
			if !ok {
				fd, err := os.Open(
					fmt.Sprintf("/proc/%d/cgroup", event.Pid),
				)
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
					bannedCgroupIDs.Put(event.CgroupID, struct{}{})
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

			// Adjust endianness if necessary
			event.Saddr = ntohl(event.Saddr)
			event.Daddr = ntohl(event.Daddr)
			event.Sport = ntohs(event.Sport)
			event.Dport = ntohs(event.Dport)

			// Convert IP addresses to net.IP
			saddr := intToIP(event.Saddr)
			daddr := intToIP(event.Daddr)

			log.With("pid", event.Pid).
				With("cgroup_id", event.CgroupID).
				With("container", container).
				With("saddr", saddr).
				With("daddr", daddr).
				With("sport", event.Sport).
				With("dport", event.Dport).
				With("size", event.Size).
				Info("Received event")

			if event.Protocol == 17 && event.Direction == 0 &&
				event.Dport == 53 {
				metrics.DNSQueryCounter.
					WithLabelValues(
						container,
					).
					Inc()
			}

			if event.Direction == 0 {
				metrics.NetworkSentBytesCounter.
					WithLabelValues(
						container,
						daddr.String(),
					).
					Add(float64(event.Size))
				metrics.NetworkSentPacketsCounter.
					WithLabelValues(
						container,
						daddr.String(),
					).
					Inc()
			} else {
				metrics.NetworkReceivedBytesCounter.
					WithLabelValues(
						container,
						daddr.String(),
					).
					Add(float64(event.Size))
				metrics.NetworkReceivedPacketsCounter.
					WithLabelValues(
						container,
						daddr.String(),
					).
					Inc()
			}
		case event := <-syscallEventChan:
			if kubernetesMode {
				if _, ok := bannedCgroupIDs.Get(event.CgroupID); ok {
					continue
				}

				sha, ok := pidToShaLRU.Get(event.Pid)
				if !ok {
					fd, err := os.Open(
						fmt.Sprintf("/proc/%d/cgroup", event.Pid),
					)
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
						bannedCgroupIDs.Put(event.CgroupID, struct{}{})
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
					With("cgroup_id", event.CgroupID).
					With("container", container).
					Debug("Received event")

				metrics.SyscallCounter.
					WithLabelValues(
						event.GetSyscallName(),
						container,
					).
					Inc()
			} else {
				log.With("syscall", event.GetSyscallName()).
					With("pid", event.Pid).
					With("cgroup_id", event.CgroupID).
					Debug("Received event")

				metrics.SyscallCounter.
					WithLabelValues(
						event.GetSyscallName(),
						strconv.FormatUint(event.Pid, 10),
					).
					Inc()
			}
		}
	}
}

func intToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func ntohs(val uint16) uint16 {
	return (val<<8)&0xff00 | val>>8
}

func ntohl(val uint32) uint32 {
	return (val<<24)&0xff000000 |
		(val<<8)&0x00ff0000 |
		(val>>8)&0x0000ff00 |
		(val>>24)&0x000000ff
}
