// Package kube provides a thin typed-client wrapper around client-go for
// observing the Variant-B agent-sandbox harness pod (a plain pod in namespace
// "agent-sandbox" that is NOT gateway-managed). Sandbox lifecycle (list/get/
// delete/shell) has been moved to internal/openshell (ADR-0010).
package kube

import (
	"context"
	"fmt"
	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client wraps a typed k8s client for harness-pod operations.
// Only the typed client is kept; the dynamic client and Sandbox CR (GVR) are
// removed because sandbox lifecycle now goes through the openshell CLI.
type Client struct {
	typed   kubernetes.Interface
	restCfg *rest.Config // stored so exec.go callers can build SPDY executors
	namespace string
}

// NewClient builds a Client from a kubeconfig context.
// namespace is the Kubernetes namespace for harness-pod operations.
// kubeconfigPath, when non-empty, is used as the explicit kubeconfig file;
// otherwise default discovery (KUBECONFIG / ~/.kube/config) applies.
func NewClient(namespace, kubeconfigPath string) (*Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	overrides := &clientcmd.ConfigOverrides{}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)

	restCfg, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kube: load kubeconfig: %w", err)
	}

	typed, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("kube: typed client: %w", err)
	}

	return &Client{
		typed:     typed,
		restCfg:   restCfg,
		namespace: namespace,
	}, nil
}

// newClientFromParts constructs a Client from pre-built interfaces; used by tests.
func newClientFromParts(typed kubernetes.Interface, namespace string) *Client {
	return &Client{
		typed:     typed,
		restCfg:   &rest.Config{}, // placeholder; not used in unit tests
		namespace: namespace,
	}
}

// TypedClient returns the underlying typed kubernetes.Interface for pod
// operations (logs, exec). Exposed for exec.go and logs.go.
func (c *Client) TypedClient() kubernetes.Interface {
	return c.typed
}

// Namespace returns the configured namespace.
func (c *Client) Namespace() string {
	return c.namespace
}

// PodInNamespace returns the first pod name in ns that matches labelSel.
// It is used by the TUI Logs tab to locate the Variant-B harness pod
// (which is a plain pod in agent-sandbox, not a gateway-managed sandbox).
//
// labelSel is a standard Kubernetes label selector string, e.g.
// "app=agent-harness,e2e-demo=true".
func PodInNamespace(ctx context.Context, c *Client, ns, labelSel string) (string, error) {
	pods, err := c.typed.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: labelSel,
	})
	if err != nil {
		slog.ErrorContext(ctx, "kube: PodInNamespace: list failed",
			"ns", ns, "selector", labelSel, "error", err)
		return "", fmt.Errorf("kube: list pods in %q with %q: %w", ns, labelSel, err)
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("kube: no pods in %q match selector %q", ns, labelSel)
	}
	// Prefer a Running pod; fall back to the first pod in the list.
	for i := range pods.Items {
		if string(pods.Items[i].Status.Phase) == "Running" {
			return pods.Items[i].Name, nil
		}
	}
	return pods.Items[0].Name, nil
}
