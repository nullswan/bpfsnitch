package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"

	"github.com/cilium/ebpf/perf"
)

func ConsumeEvents[T BpfEvent](
	ctx context.Context,
	log *slog.Logger,
	evReader *perf.Reader,
	evCh chan *T,
) {
	log.Info("Starting event reader")

	for {
		select {
		case <-ctx.Done():
			log.Info("Context done, stopping event reader")
			return
		default:
			record, err := evReader.Read()
			if err != nil {
				log.With("error", err).Error("Failed to read event")
				continue
			}

			if record.LostSamples > 0 {
				log.With("lost_samples", record.LostSamples).
					Warn("Lost samples")
				continue
			}

			var ev T
			err = binary.Read(
				bytes.NewReader(record.RawSample),
				binary.LittleEndian,
				&ev,
			)
			if err != nil {
				log.With("error", err).Error("Failed to decode event")
				continue
			}

			evCh <- &ev
		}
	}
}
