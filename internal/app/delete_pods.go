package app

import (
	"context"
	"log/slog"

	"github.com/nullswan/bpfsnitch/internal/metrics"
)

func deletePods(
	ctx context.Context,
	logger *slog.Logger,
	deletedPodsChan chan string,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case podID := <-deletedPodsChan:
			for _, counter := range metrics.PodBasedMetrics {
				logger.With("pod", podID).Info("Deleted pod-based metrics")
				counter.DeleteLabelValues(podID)
			}
		}
	}
}
