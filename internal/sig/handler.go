package sig

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/nullswan/bpfsnitch/internal/bpf"
)

func SetupHandler(
	cancel context.CancelFunc,
	bpfCtx *bpf.KBContext,
	log *slog.Logger,
) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.With("signal", sig).Info("Received signal, cancelling context")

		cancel()
		for _, tp := range bpfCtx.Tps {
			tp.Close()
		}
		for _, kp := range bpfCtx.Kps {
			kp.Close()
		}

		bpfCtx.SyscallRingBuffer.Close()
		bpfCtx.NetworkRingBuffer.Close()

		log.Info("Closed event reader")
	}()
}
