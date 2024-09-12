package workload

import "os"

var runtimeSockets = []string{
	"/run/containerd/containerd.sock",
	"/run/crio/crio.sock",
	"/var/run/cri-dockerd.sock",
}

func IsSocketPresent() bool {
	for _, endpoint := range runtimeSockets {
		if _, err := os.Stat(endpoint); err == nil {
			return true
		}
	}

	return false
}
