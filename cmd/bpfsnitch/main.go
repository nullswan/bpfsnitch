package main

import (
	"os"

	"github.com/nullswan/bpfsnitch/internal/app"
	"github.com/nullswan/bpfsnitch/internal/logger"
)

func main() {
	log := logger.Init()

	if err := app.Run(log); err != nil {
		log.With("error", err).Error("Failed to run app")
		os.Exit(1)
	}
}
