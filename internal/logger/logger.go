package logger

import (
	"log/slog"
	"os"
)

func Init() *slog.Logger {
	loggerHandlerOpts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	if os.Getenv("DEBUG") != "" {
		loggerHandlerOpts.Level = slog.LevelDebug
	}

	return slog.New(
		slog.NewTextHandler(os.Stdout, loggerHandlerOpts),
	)
}
