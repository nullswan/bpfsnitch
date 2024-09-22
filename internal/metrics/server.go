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
