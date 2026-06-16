package kube

import (
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
)

// StreamLogs streams the logs of container in pod (in namespace ns) to w until
// ctx is cancelled or EOF is reached.
//
// container is the name of the container inside the pod.  For the Variant-B
// harness pod in agent-sandbox this is typically "agent".
func StreamLogs(ctx context.Context, c *Client, pod, ns, container string, w io.Writer) error {
	if pod == "" {
		return fmt.Errorf("logs: pod name is empty")
	}

	opts := &corev1.PodLogOptions{
		Container: container,
		Follow:    true,
		TailLines: int64Ptr(200),
	}

	req := c.typed.CoreV1().Pods(ns).GetLogs(pod, opts)
	stream, err := req.Stream(ctx)
	if err != nil {
		return fmt.Errorf("logs: open stream for pod %q: %w", pod, err)
	}
	defer stream.Close()

	if _, err := io.Copy(w, stream); err != nil && ctx.Err() == nil {
		return fmt.Errorf("logs: stream copy: %w", err)
	}
	return nil
}

// LogsSince returns up to tailLines lines of logs from container in pod since
// sinceSeconds.  It does NOT follow; use StreamLogs for live tailing.
//
// container is the name of the container inside the pod.
func LogsSince(ctx context.Context, c *Client, pod, ns, container string, tailLines int64, sinceSeconds *int64) (io.ReadCloser, error) {
	if pod == "" {
		return nil, fmt.Errorf("logs: pod name is empty")
	}
	opts := &corev1.PodLogOptions{
		Container:    container,
		Follow:       false,
		TailLines:    &tailLines,
		SinceSeconds: sinceSeconds,
	}
	req := c.typed.CoreV1().Pods(ns).GetLogs(pod, opts)
	stream, err := req.Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("logs: open non-follow stream for pod %q: %w", pod, err)
	}
	return stream, nil
}

func int64Ptr(v int64) *int64 { return &v }
