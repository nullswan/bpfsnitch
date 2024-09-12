package workload

import (
	"context"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func getRuntimeServiceClient() (runtimeapi.RuntimeServiceClient, *grpc.ClientConn, error) {
	var runtimeEndpoint string
	for _, endpoint := range runtimeSockets {
		if _, err := os.Stat(endpoint); err == nil {
			runtimeEndpoint = endpoint
			break
		}
	}

	if runtimeEndpoint == "" {
		return nil, nil, errors.New("no runtime socket found")
	}

	serverAddr := "unix://" + runtimeEndpoint
	conn, err := grpc.NewClient(
		serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"failed to connect to %s: %w",
			serverAddr,
			err,
		)
	}

	runtimeClient := runtimeapi.NewRuntimeServiceClient(conn)
	return runtimeClient, conn, nil
}

func getContainers(
	ctx context.Context,
	runtimeClient runtimeapi.RuntimeServiceClient,
) ([]*runtimeapi.Container, error) {
	req := &runtimeapi.ListContainersRequest{
		Filter: &runtimeapi.ContainerFilter{
			State: &runtimeapi.ContainerStateValue{
				State: runtimeapi.ContainerState_CONTAINER_RUNNING,
			},
		},
	}
	resp, err := runtimeClient.ListContainers(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}
	return resp.Containers, nil
}

func getPods(
	ctx context.Context,
	runtimeClient runtimeapi.RuntimeServiceClient,
) ([]*runtimeapi.PodSandbox, error) {
	req := &runtimeapi.ListPodSandboxRequest{
		Filter: &runtimeapi.PodSandboxFilter{
			State: &runtimeapi.PodSandboxStateValue{
				State: runtimeapi.PodSandboxState_SANDBOX_READY,
			},
		},
	}
	resp, err := runtimeClient.ListPodSandbox(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}
	return resp.Items, nil
}
