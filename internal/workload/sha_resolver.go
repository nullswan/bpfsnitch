package workload

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/nullswan/bpfsnitch/pkg/lru"
	"google.golang.org/grpc"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	internalLRUCacheSize = 1000
)

type ShaResolver struct {
	containerShaToPodName *lru.Cache[string, string]

	logger *slog.Logger
	client runtimeapi.RuntimeServiceClient
	conn   *grpc.ClientConn
}

func (r *ShaResolver) Resolve(sha string) (string, error) {
	v, ok := r.containerShaToPodName.Get(sha)
	if ok {
		return v, nil
	}

	err := r.UpdateCache()
	if err != nil {
		return "", fmt.Errorf("failed to update cache: %w", err)
	}

	v, ok = r.containerShaToPodName.Get(sha)
	if !ok {
		return "", fmt.Errorf("sha %s not found in cache", sha)
	}

	return v, nil
}

func (r *ShaResolver) UpdateCache() error {
	ctx := context.Background()

	pods, err := getPods(r.client, ctx)
	if err != nil {
		return fmt.Errorf("failed to list pods: %w", err)
	}

	podMap := make(map[string]*runtimeapi.PodSandbox)
	for _, pod := range pods {
		podMap[pod.Id] = pod
	}

	containers, err := getContainers(r.client, ctx)
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	for _, container := range containers {
		containerPodId := container.GetPodSandboxId()
		containerPod, ok := podMap[containerPodId]
		if !ok {
			r.logger.Warn(
				"container %s has no associated pod",
				"container_id",
				container.GetId(),
				"pod_id",
				containerPodId,
			)
			continue
		}

		r.containerShaToPodName.Put(
			container.GetId(),
			containerPod.GetMetadata().GetName(),
		)
	}

	return nil
}

func (r *ShaResolver) Close() {
	r.conn.Close()
}

func NewShaResolver() (*ShaResolver, error) {
	containerShaToPodName := lru.New[string, string](internalLRUCacheSize)

	client, conn, err := getRuntimeServiceClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get runtime service client: %w", err)
	}

	return &ShaResolver{
		containerShaToPodName: containerShaToPodName,

		client: client,
		conn:   conn,
	}, nil
}
