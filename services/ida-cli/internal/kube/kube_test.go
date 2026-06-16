package kube

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

const (
	testNS    = "openshell"
	testOwner = "alice"
)

// newFakeClient builds a *Client backed by a fake typed client.
// The dynamic client is removed (ADR-0010); Sandbox lifecycle goes through openshell.
func newFakeClient(t *testing.T) *Client {
	t.Helper()
	typedCli := kubefake.NewSimpleClientset()
	return newClientFromParts(typedCli, testNS)
}

// newFakeClientWithPods builds a *Client backed by a fake typed client
// pre-seeded with the provided Pod objects.
func newFakeClientWithPods(t *testing.T, pods ...*corev1.Pod) *Client {
	t.Helper()
	objs := make([]runtime.Object, len(pods))
	for i, p := range pods {
		objs[i] = p
	}
	typedCli := kubefake.NewSimpleClientset(objs...)
	return newClientFromParts(typedCli, testNS)
}

// ---------------------------------------------------------------------------
// NewClient
// ---------------------------------------------------------------------------

func TestNewClient_MissingKubeconfig(t *testing.T) {
	// Point KUBECONFIG at a nonexistent path so clientcmd fails to find a cluster.
	t.Setenv("KUBECONFIG", "/nonexistent/path/to/kubeconfig")
	_, err := NewClient(testNS, "")
	// NewClient must fail — not silently fall back to an empty config.
	assert.Error(t, err, "NewClient should fail when kubeconfig is missing")
}

// ---------------------------------------------------------------------------
// TypedClient / Namespace accessors
// ---------------------------------------------------------------------------

func TestClient_Accessors(t *testing.T) {
	c := newFakeClient(t)
	assert.NotNil(t, c.TypedClient(), "TypedClient must not be nil")
	assert.Equal(t, testNS, c.Namespace())
}

// ---------------------------------------------------------------------------
// PodInNamespace
// ---------------------------------------------------------------------------

func TestPodInNamespace_FindsRunningPod(t *testing.T) {
	const hashLabel = "app"
	const hashVal = "agent-harness"
	selector := hashLabel + "=" + hashVal

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "harness-pod-1",
			Namespace: testNS,
			Labels:    map[string]string{hashLabel: hashVal},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	c := newFakeClientWithPods(t, pod)
	got, err := PodInNamespace(context.Background(), c, testNS, selector)
	require.NoError(t, err)
	assert.Equal(t, "harness-pod-1", got)
}

func TestPodInNamespace_PrefersRunningOverPending(t *testing.T) {
	const label = "e2e=true"

	pendingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pending-pod", Namespace: testNS,
			Labels: map[string]string{"e2e": "true"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}
	runningPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "running-pod", Namespace: testNS,
			Labels: map[string]string{"e2e": "true"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	c := newFakeClientWithPods(t, pendingPod, runningPod)
	got, err := PodInNamespace(context.Background(), c, testNS, label)
	require.NoError(t, err)
	assert.Equal(t, "running-pod", got)
}

func TestPodInNamespace_EmptyList_ReturnsError(t *testing.T) {
	c := newFakeClient(t) // no pods seeded
	_, err := PodInNamespace(context.Background(), c, testNS, "app=agent-harness")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no pods")
}

// ---------------------------------------------------------------------------
// LogsSince (logs.go) — unit test with a fake pod log server via fake typed client
// ---------------------------------------------------------------------------

func TestLogsSince_ReturnsReader(t *testing.T) {
	// kubefake returns an empty body for GetLogs; we just verify no error and
	// that the reader is non-nil (the stream can be read, even if empty).
	typedCli := kubefake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: testNS},
	})
	c := newClientFromParts(typedCli, testNS)

	rc, err := LogsSince(context.Background(), c, "my-pod", testNS, "agent", 50, nil)
	require.NoError(t, err)
	defer rc.Close()

	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	// The fake returns empty body; the important thing is no error.
	_ = data
}

func TestLogsSince_EmptyPodName(t *testing.T) {
	c := newFakeClient(t)
	_, err := LogsSince(context.Background(), c, "", testNS, "agent", 50, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pod name is empty")
}

func TestStreamLogs_EmptyPodName(t *testing.T) {
	c := newFakeClient(t)
	err := StreamLogs(context.Background(), c, "", testNS, "agent", io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pod name is empty")
}

// ---------------------------------------------------------------------------
// StreamLogs — cancelled context
// ---------------------------------------------------------------------------

func TestStreamLogs_ContextCancelled(t *testing.T) {
	typedCli := kubefake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "stream-pod", Namespace: testNS},
	})
	c := newClientFromParts(typedCli, testNS)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	// A cancelled context should not cause StreamLogs to panic; it may return
	// an error (context cancelled) or nil if the fake returns EOF immediately.
	err := StreamLogs(ctx, c, "stream-pod", testNS, "agent", io.Discard)
	// The kubefake client returns an empty body synchronously, so StreamLogs
	// completes immediately with nil rather than blocking. Accept either.
	_ = err
}

// ---------------------------------------------------------------------------
// int64Ptr (internal helper in logs.go)
// ---------------------------------------------------------------------------

func TestInt64Ptr(t *testing.T) {
	v := int64(42)
	p := int64Ptr(v)
	require.NotNil(t, p)
	assert.Equal(t, v, *p)
}
