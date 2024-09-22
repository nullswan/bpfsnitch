package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"

	"github.com/cilium/ebpf/ringbuf"
)

func ConsumeEvents[T Event](
	ctx context.Context,
	log *slog.Logger,
	evReader *ringbuf.Reader,
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

			ev := new(T)
			err = binary.Read(
				bytes.NewReader(record.RawSample),
				binary.LittleEndian,
				ev,
			)
			if err != nil {
				log.With("error", err).Error("Failed to decode event")
				continue
			}

			evCh <- ev
		}
	}
}
