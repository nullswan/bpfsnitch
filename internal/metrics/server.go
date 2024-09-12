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

var SyscallCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "syscall_counter",
		Help: "Number of syscalls",
	},
	[]string{"syscall", "container"},
)

func StartServer(log *slog.Logger, cancel context.CancelFunc, port uint32) {
	http.Handle("/metrics", promhttp.Handler())

	log.With("port", port).Info("Starting metrics server")
	err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		log.With("error", err).Error("Failed to start metrics server")
		cancel()
	}
}

func RegisterMetrics() {
	// Remove all builtin metrics that are produced by prometheus client.
	// TODO: Remove promhttp_metric_handler_requests_total && promhttp_metric_handler_requests_in_flight
	prometheus.Unregister(collectors.NewGoCollector())
	prometheus.Unregister(collectors.NewProcessCollector(
		collectors.ProcessCollectorOpts{},
	))

	prometheus.MustRegister(SyscallCounter)
}
