package workload

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/nullswan/bpfsnitch/pkg/lru"
)

var (
	ErrCgroupIDBanned       = errors.New("cgroup id is banned")
	ErrCgroupIDNotContainer = errors.New("cgroup id is not container")
)

func ResolvePod(
	pid uint64,
	cgroupID uint64,
	pidToShaLRU *lru.Cache[uint64, string],
	bannedCgroupIDs *lru.Cache[uint64, struct{}],
	shaResolver *ShaResolver,
	procPath string,
	log *slog.Logger,
) (string, error) {
	if _, ok := bannedCgroupIDs.Get(cgroupID); ok {
		return "", ErrCgroupIDBanned
	}

	sha, ok := pidToShaLRU.Get(pid)
	if !ok {
		sha, err := readShaFromCgroup(
			pid,
			cgroupID,
			bannedCgroupIDs,
			procPath,
			log,
		)
		if err != nil {
			return "", fmt.Errorf("failed to read sha from cgroup: %w", err)
		}
		pidToShaLRU.Put(pid, sha)
	}

	pod, err := shaResolver.Resolve(sha)
	if err != nil {
		return "", fmt.Errorf("failed to resolve sha: %w", err)
	}

	return pod, nil
}

var reKubeContainerd = regexp.MustCompile(`([a-f0-9]{64})\.scope`)

func readShaFromCgroup(
	pid uint64,
	cgroupID uint64,
	bannedCgroupIDs *lru.Cache[uint64, struct{}],
	procPath string,
	log *slog.Logger,
) (string, error) {
	fd, err := os.Open(fmt.Sprintf("/%s/%d/cgroup", procPath, pid))
	if err != nil {
		return "", fmt.Errorf("failed to open cgroup file: %w", err)
	}
	defer fd.Close()

	content, err := io.ReadAll(fd)
	if err != nil {
		return "", fmt.Errorf("failed to read cgroup file: %w", err)
	}

	// format local containerd
	contentStr := string(content)
	if strings.Contains(contentStr, "k8s.io") {
		sha := strings.TrimSpace(
			contentStr[strings.LastIndex(contentStr, "/")+1:],
		)
		return sha, nil
	}

	// format SCW, AWS
	// 0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod7bd1a2a3_0861_4fe1_be78_9c76385b3dc0.slice/cri-containerd-1579a01cfce4b1e74529c17bed485d86b871b58f13348c773076b101df4ff62d.scope
	if strings.Contains(contentStr, "cri-containerd") {
		match := reKubeContainerd.FindStringSubmatch(contentStr)
		if len(match) == 2 { // nolint: mnd
			return match[1], nil
		}
	}

	log.With("cgroup_id", cgroupID).Debug("Banning cgroup id")
	bannedCgroupIDs.Put(cgroupID, struct{}{})
	return "", ErrCgroupIDNotContainer
}
