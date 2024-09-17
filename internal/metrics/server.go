package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var DNSQueryCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "dns_query_counter",
		Help: "Number of DNS queries",
	},
	[]string{"container"},
)

var SyscallCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "syscall_counter",
		Help: "Number of syscalls",
	},
	[]string{"syscall", "container"},
)

var NetworkReceivedBytesCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "network_received_bytes_counter",
		Help: "Number of bytes received",
	},
	[]string{"container", "remote_ip"},
)

var NetworkReceivedPacketsCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "network_received_packets_counter",
		Help: "Number of packets received",
	},
	[]string{"container", "remote_ip"},
)

var NetworkSentBytesCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "network_sent_bytes_counter",
		Help: "Number of bytes sent",
	},
	[]string{"container", "remote_ip"},
)

var NetworkSentPacketsCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "network_sent_packets_counter",
		Help: "Number of packets sent",
	},
	[]string{"container", "remote_ip"},
)

func StartServer(log *slog.Logger, cancel context.CancelFunc, port uint64) {
	http.Handle("/metrics", promhttp.Handler())

	log.With("port", port).Info("Starting metrics server")
	err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil) // nolint:gosec
	if err != nil {
		log.With("error", err).Error("Failed to start metrics server")
		cancel()
	}
}

const promPrefix = "bpfsnitch_"

func RegisterMetrics() {
	// Remove all builtin metrics that are produced by prometheus client.
	// TODO: Remove promhttp_metric_handler_requests_total && promhttp_metric_handler_requests_in_flight
	prometheus.Unregister(collectors.NewGoCollector())
	prometheus.Unregister(collectors.NewProcessCollector(
		collectors.ProcessCollectorOpts{},
	))

	// Create a custom registerer with a prefix
	registerer := prometheus.WrapRegistererWithPrefix(
		promPrefix,
		prometheus.DefaultRegisterer,
	)

	registerer.MustRegister(SyscallCounter)
	registerer.MustRegister(DNSQueryCounter)
	registerer.MustRegister(NetworkReceivedBytesCounter)
	registerer.MustRegister(NetworkReceivedPacketsCounter)
	registerer.MustRegister(NetworkSentBytesCounter)
	registerer.MustRegister(NetworkSentPacketsCounter)
}
