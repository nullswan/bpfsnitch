package workload

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/nullswan/bpfsnitch/pkg/lru"
)

func ResolveContainer(
	pid uint64,
	cgroupID uint64,
	pidToShaLRU *lru.Cache[uint64, string],
	bannedCgroupIDs *lru.Cache[uint64, struct{}],
	shaResolver *ShaResolver,
	procPath string,
	log *slog.Logger,
) (string, bool) {
	if _, ok := bannedCgroupIDs.Get(cgroupID); ok {
		return "", false
	}

	sha, ok := pidToShaLRU.Get(pid)
	if !ok {
		sha, ok = readShaFromCgroup(
			pid,
			cgroupID,
			bannedCgroupIDs,
			procPath,
			log,
		)
		if !ok {
			return "", false
		}
		pidToShaLRU.Put(pid, sha)
	}

	container, err := shaResolver.Resolve(sha)
	if err != nil {
		log.With("error", err).With("sha", sha).Error("Failed to resolve sha")
		return "", false
	}

	return container, true
}

func readShaFromCgroup(
	pid uint64,
	cgroupID uint64,
	bannedCgroupIDs *lru.Cache[uint64, struct{}],
	procPath string,
	log *slog.Logger,
) (string, bool) {
	fd, err := os.Open(fmt.Sprintf("/%s/%d/cgroup", procPath, pid))
	if err != nil {
		log.With("error", err).Error("Failed to open cgroup file")
		return "", false
	}
	defer fd.Close()

	content, err := io.ReadAll(fd)
	if err != nil {
		log.With("error", err).Error("Failed to read cgroup file")
		return "", false
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "k8s.io") {
		bannedCgroupIDs.Put(cgroupID, struct{}{})
		return "", false
	}

	sha := strings.TrimSpace(contentStr[strings.LastIndex(contentStr, "/")+1:])
	return sha, true
}
