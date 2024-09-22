package workload

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nullswan/bpfsnitch/pkg/lru"
	"google.golang.org/grpc"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	internalLRUCacheSize = 1000
	shaResolverTimeout   = 5 * time.Second
)

// ContainerInfo stores information about a container's associated pod.
type ContainerInfo struct {
	PodID   string
	PodName string
}

type ContainerSha string

type ShaResolver struct {
	containerToPodInfo *lru.Cache[ContainerSha, *ContainerInfo]

	logger *slog.Logger
	client runtimeapi.RuntimeServiceClient
	conn   *grpc.ClientConn

	// Channel for expired pods
	ExpiredPodChan chan string

	// Map of known pod IDs to pod metadata
	knownPods      map[string]*runtimeapi.PodSandbox
	knownPodsMutex sync.Mutex
}

// NewShaResolver creates a new ShaResolver instance.
func NewShaResolver(
	logger *slog.Logger,
	expiredPodChan chan string,
) (*ShaResolver, error) {
	containerToPodInfo := lru.New[ContainerSha, *ContainerInfo](
		internalLRUCacheSize,
	)

	client, conn, err := getRuntimeServiceClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get runtime service client: %w", err)
	}

	return &ShaResolver{
		containerToPodInfo: containerToPodInfo,
		client:             client,
		conn:               conn,
		logger:             logger,
		ExpiredPodChan:     expiredPodChan,
		knownPods:          make(map[string]*runtimeapi.PodSandbox),
		knownPodsMutex:     sync.Mutex{},
	}, nil
}

// Resolve returns the pod name associated with a given container SHA.
func (r *ShaResolver) Resolve(inputSha string) (string, error) {
	sha := ContainerSha(inputSha)

	v, ok := r.containerToPodInfo.Get(sha)
	if ok {
		return v.PodName, nil
	}

	err := r.UpdateCache()
	if err != nil {
		return "", fmt.Errorf("failed to update cache: %w", err)
	}

	v, ok = r.containerToPodInfo.Get(sha)
	if !ok {
		return "", fmt.Errorf("sha %s not found in cache", sha)
	}

	return v.PodName, nil
}

// UpdateCache updates the cache with the latest pod and container information.
func (r *ShaResolver) UpdateCache() error {
	ctx, cancel := context.WithTimeout(context.Background(), shaResolverTimeout)
	defer cancel()

	pods, err := getPods(ctx, r.client)
	if err != nil {
		return fmt.Errorf("failed to list pods: %w", err)
	}

	currentPods := make(map[string]*runtimeapi.PodSandbox)
	for _, pod := range pods {
		currentPods[pod.Id] = pod
	}

	r.detectExpiredPods(currentPods)

	r.knownPodsMutex.Lock()
	r.knownPods = currentPods
	r.knownPodsMutex.Unlock()

	containers, err := getContainers(ctx, r.client)
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	for _, container := range containers {
		containerID := container.GetId()
		podID := container.GetPodSandboxId()

		pod, ok := currentPods[podID]
		if !ok {
			r.logger.Warn(
				"container has no associated pod",
				"container_id", containerID,
				"pod_id", podID,
			)
			continue
		}

		r.containerToPodInfo.Put(
			ContainerSha(containerID),
			&ContainerInfo{
				PodID:   podID,
				PodName: pod.GetMetadata().GetName(),
			},
		)
	}
	return nil
}

// detectExpiredPods detects pods that are no longer running and sends them to the expired pod channel.
func (r *ShaResolver) detectExpiredPods(
	currentPods map[string]*runtimeapi.PodSandbox,
) {
	r.knownPodsMutex.Lock()
	defer r.knownPodsMutex.Unlock()

	for podID, pod := range r.knownPods {
		if _, exists := currentPods[podID]; !exists {
			r.logger.Info(
				"Pod expired",
				"pod_id",
				podID,
				"pod_name",
				pod.GetMetadata().GetName(),
			)

			select {
			case r.ExpiredPodChan <- podID:
			default:
				r.logger.Warn("Expired pod channel is full", "pod_id", podID)
			}

			r.removePodFromCache(podID)
		}
	}
}

// removePodFromCache removes all containers associated with a given pod ID from the cache.
func (r *ShaResolver) removePodFromCache(podID string) {
	keysToRemove := []ContainerSha{}

	r.containerToPodInfo.ForEach(
		func(containerID ContainerSha, info *ContainerInfo) bool {
			if info.PodID == podID {
				keysToRemove = append(keysToRemove, containerID)
			}
			return true
		},
	)

	for _, key := range keysToRemove {
		r.containerToPodInfo.Remove(key)
	}
}

// Close closes the ShaResolver instance.
func (r *ShaResolver) Close() {
	r.conn.Close()
}
