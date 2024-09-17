package profile

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/grafana/pyroscope-go"
)

func SetupProfiling(log *slog.Logger) error {
	serverAddress := os.Getenv("PYROSCOPE_SERVER")
	if serverAddress == "" {
		return fmt.Errorf("PYROSCOPE_SERVER is not set")
	}

	user := os.Getenv("PYROSCOPE_USER")
	if user == "" {
		log.Warn("PYROSCOPE_USER is not set")
	}

	password := os.Getenv("PYROSCOPE_PASSWORD")
	if password == "" {
		log.Warn("PYROSCOPE_PASSWORD is not set")
	}

	pyroscope.Start(pyroscope.Config{
		ApplicationName:   "bpfsnitch",
		ServerAddress:     serverAddress,
		BasicAuthUser:     user,
		BasicAuthPassword: password,
		Logger:            pyroscope.StandardLogger,
		Tags:              map[string]string{"hostname": os.Getenv("HOSTNAME")},
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileInuseObjects,
			pyroscope.ProfileInuseSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileMutexCount,
			pyroscope.ProfileMutexDuration,
			pyroscope.ProfileBlockCount,
			pyroscope.ProfileBlockDuration,
		},
	})

	return nil
}
