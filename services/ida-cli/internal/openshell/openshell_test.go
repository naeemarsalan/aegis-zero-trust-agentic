package openshell

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// fakeRunner — test double for Runner
// ---------------------------------------------------------------------------

// fakeRunner records each call and returns canned responses keyed by a string
// formed from the joined args. A zero-value fakeRunner returns empty bytes and
// nil errors for every call.
type fakeRunner struct {
	// responses maps the string representation of args (joined with " ") to the
	// bytes that Run should return.
	responses map[string][]byte
	// errors maps the same key to an error that Run should return.
	errors map[string]error
	// calls records every (bin, args) pair presented to Run.
	calls [][]string
	// streamErr is returned by RunStream.
	streamErr error
}

func (f *fakeRunner) Run(_ context.Context, bin string, args ...string) ([]byte, error) {
	key := bin
	for _, a := range args {
		key += " " + a
	}
	call := append([]string{bin}, args...)
	f.calls = append(f.calls, call)
	if f.errors != nil {
		if err, ok := f.errors[key]; ok {
			return nil, err
		}
	}
	if f.responses != nil {
		if b, ok := f.responses[key]; ok {
			return b, nil
		}
	}
	return []byte("[]"), nil
}

func (f *fakeRunner) RunStream(_ context.Context, _ string, w io.Writer, _ ...string) error {
	return f.streamErr
}

// lastCall returns the most-recent set of arguments passed to Run.
func (f *fakeRunner) lastCall() []string {
	if len(f.calls) == 0 {
		return nil
	}
	return f.calls[len(f.calls)-1]
}

// ---------------------------------------------------------------------------
// Fixture JSON
// ---------------------------------------------------------------------------

// listFixture is a top-level JSON array as produced by `openshell sandbox list
// -o json` (crates/openshell-cli/src/output.rs print_output_collection).
const listFixture = `[
  {
    "id": "sb1",
    "name": "alice-task",
    "labels": {
      "nvidia-ida/owner": "alice",
      "nvidia-ida/scope": "read-only",
      "nvidia-ida/ttl-minutes": "60"
    },
    "resource_version": 3,
    "created_at": "2026-06-16 10:00:00",
    "phase": "Ready",
    "current_policy_version": 1
  }
]`

const listFixtureMulti = `[
  {
    "id": "sb1",
    "name": "alice-task",
    "labels": {"nvidia-ida/owner": "alice","nvidia-ida/scope": "read-only","nvidia-ida/ttl-minutes": "60"},
    "resource_version": 1,
    "created_at": "2026-06-16 10:00:00",
    "phase": "Ready",
    "current_policy_version": 1
  },
  {
    "id": "sb2",
    "name": "bob-workspace",
    "labels": {"nvidia-ida/owner": "bob","nvidia-ida/scope": "read-write","nvidia-ida/ttl-minutes": "120"},
    "resource_version": 2,
    "created_at": "2026-06-16 11:00:00",
    "phase": "Error",
    "current_policy_version": 0
  }
]`

const getSingleFixture = `{
  "id": "sb99",
  "name": "carol-debug",
  "labels": {"nvidia-ida/owner": "carol","nvidia-ida/scope": "admin","nvidia-ida/ttl-minutes": "30"},
  "resource_version": 7,
  "created_at": "2026-06-16 09:00:00",
  "phase": "Deleting",
  "current_policy_version": 2
}`

// ---------------------------------------------------------------------------
// List tests
// ---------------------------------------------------------------------------

func TestList_ParsesArrayJSON(t *testing.T) {
	r := &fakeRunner{
		responses: map[string][]byte{
			"openshell sandbox list -o json --selector nvidia-ida/owner=alice": []byte(listFixture),
		},
	}
	cli := New("openshell", GatewayConfig{}, "openshell", r)

	sandboxes, err := cli.List(context.Background(), "alice")
	require.NoError(t, err)
	require.Len(t, sandboxes, 1)

	sb := sandboxes[0]
	assert.Equal(t, "alice-task", sb.Name)
	assert.Equal(t, "sb1", sb.ID)
	assert.Equal(t, "openshell", sb.Namespace)
	assert.Equal(t, "Ready", sb.Phase)
	assert.Equal(t, "read-only", sb.Scope)
	assert.Equal(t, "60", sb.TTLMinutes)
	assert.Equal(t, "alice", sb.Owner)
	assert.Equal(t, "2026-06-16 10:00:00", sb.CreatedAt)
	assert.Equal(t, "", sb.AccessHint, "AccessHint must be empty (no annotations in CLI JSON)")
	assert.Equal(t, "", sb.Selector, "Selector must be empty (no pod-selector in CLI JSON)")
}

func TestList_EmptyArray(t *testing.T) {
	r := &fakeRunner{} // default returns "[]"
	cli := New("openshell", GatewayConfig{}, "openshell", r)

	sandboxes, err := cli.List(context.Background(), "nobody")
	require.NoError(t, err)
	assert.Empty(t, sandboxes)
}

func TestList_MalformedJSON_ReturnsError(t *testing.T) {
	r := &fakeRunner{
		responses: map[string][]byte{
			"openshell sandbox list -o json": []byte(`NOT JSON`),
		},
	}
	cli := New("openshell", GatewayConfig{}, "openshell", r)

	_, err := cli.List(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse list json")
}

func TestList_RunnerError_ReturnsError(t *testing.T) {
	r := &fakeRunner{
		errors: map[string]error{
			"openshell sandbox list -o json": fmt.Errorf("gateway unreachable"),
		},
	}
	cli := New("openshell", GatewayConfig{}, "openshell", r)

	_, err := cli.List(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list")
}

func TestList_MultipleItems(t *testing.T) {
	r := &fakeRunner{
		responses: map[string][]byte{
			"openshell sandbox list -o json": []byte(listFixtureMulti),
		},
	}
	cli := New("openshell", GatewayConfig{}, "ns", r)

	sandboxes, err := cli.List(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, sandboxes, 2)

	// Second item has phase "Error" which normalises to "Failed".
	assert.Equal(t, "Failed", sandboxes[1].Phase)
	assert.Equal(t, "bob", sandboxes[1].Owner)
	assert.Equal(t, "read-write", sandboxes[1].Scope)
}

// ---------------------------------------------------------------------------
// Get tests
// ---------------------------------------------------------------------------

func TestGet_ParsesObjectJSON(t *testing.T) {
	r := &fakeRunner{
		responses: map[string][]byte{
			"openshell sandbox get carol-debug -o json": []byte(getSingleFixture),
		},
	}
	cli := New("openshell", GatewayConfig{}, "myns", r)

	sb, err := cli.Get(context.Background(), "carol-debug")
	require.NoError(t, err)
	assert.Equal(t, "carol-debug", sb.Name)
	assert.Equal(t, "sb99", sb.ID)
	assert.Equal(t, "myns", sb.Namespace)
	assert.Equal(t, "Terminating", sb.Phase) // "Deleting" normalises to "Terminating"
	assert.Equal(t, "admin", sb.Scope)
	assert.Equal(t, "carol", sb.Owner)
}

func TestGet_RunnerError_ReturnsError(t *testing.T) {
	r := &fakeRunner{
		errors: map[string]error{
			"openshell sandbox get missing -o json": fmt.Errorf("not found"),
		},
	}
	cli := New("openshell", GatewayConfig{}, "ns", r)

	_, err := cli.Get(context.Background(), "missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}

// ---------------------------------------------------------------------------
// Delete tests
// ---------------------------------------------------------------------------

func TestDelete_PassesName(t *testing.T) {
	r := &fakeRunner{
		responses: map[string][]byte{
			"openshell sandbox delete sb-to-del": []byte(`deleted`),
		},
	}
	cli := New("openshell", GatewayConfig{}, "ns", r)

	err := cli.Delete(context.Background(), "sb-to-del")
	require.NoError(t, err)

	last := r.lastCall()
	require.NotNil(t, last)
	assert.Contains(t, last, "delete")
	assert.Contains(t, last, "sb-to-del")
}

func TestDelete_RunnerError_ReturnsError(t *testing.T) {
	r := &fakeRunner{
		errors: map[string]error{
			"openshell sandbox delete ghost": fmt.Errorf("not found"),
		},
	}
	cli := New("openshell", GatewayConfig{}, "ns", r)

	err := cli.Delete(context.Background(), "ghost")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ghost")
}

// ---------------------------------------------------------------------------
// Gateway flag assertions
// ---------------------------------------------------------------------------

func TestList_GatewayFlags_AllSet(t *testing.T) {
	r := &fakeRunner{}
	gw := GatewayConfig{
		Endpoint: "https://gw.example.com",
		Name:     "prod",
		Insecure: true,
	}
	cli := New("openshell", gw, "ns", r)

	_, _ = cli.List(context.Background(), "")
	last := r.lastCall()
	require.NotNil(t, last)

	// Verify the gateway flags appear in order before the sub-command args.
	joined := fmt.Sprint(last)
	assert.Contains(t, joined, "--gateway-endpoint")
	assert.Contains(t, joined, "https://gw.example.com")
	assert.Contains(t, joined, "-g")
	assert.Contains(t, joined, "prod")
	assert.Contains(t, joined, "--gateway-insecure")
}

func TestList_GatewayFlags_None(t *testing.T) {
	r := &fakeRunner{}
	cli := New("openshell", GatewayConfig{}, "ns", r)

	_, _ = cli.List(context.Background(), "")
	last := r.lastCall()
	require.NotNil(t, last)

	joined := fmt.Sprint(last)
	assert.NotContains(t, joined, "--gateway-endpoint")
	assert.NotContains(t, joined, "-g")
	assert.NotContains(t, joined, "--gateway-insecure")
}

func TestList_SelectorArg_WhenOwnerSet(t *testing.T) {
	r := &fakeRunner{}
	cli := New("openshell", GatewayConfig{}, "ns", r)

	_, _ = cli.List(context.Background(), "alice")
	last := r.lastCall()
	require.NotNil(t, last)

	joined := fmt.Sprint(last)
	assert.Contains(t, joined, "--selector")
	assert.Contains(t, joined, "nvidia-ida/owner=alice")
}

func TestList_NoSelectorArg_WhenOwnerEmpty(t *testing.T) {
	r := &fakeRunner{}
	cli := New("openshell", GatewayConfig{}, "ns", r)

	_, _ = cli.List(context.Background(), "")
	last := r.lastCall()
	require.NotNil(t, last)

	joined := fmt.Sprint(last)
	assert.NotContains(t, joined, "--selector")
}

// ---------------------------------------------------------------------------
// normalisePhase table-driven tests
// ---------------------------------------------------------------------------

func TestNormalisePhase(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"Ready", "Ready"},
		{"Provisioning", "Provisioning"},
		{"Error", "Failed"},
		{"Deleting", "Terminating"},
		{"Unknown", "Unknown"},
		{"Unspecified", "Unknown"},
		{"", "Unknown"},
		{"SomeFuturePhase", "Unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := normalisePhase(tc.input)
			assert.Equal(t, tc.want, got,
				"normalisePhase(%q) should return %q", tc.input, tc.want)
		})
	}
}

// ---------------------------------------------------------------------------
// toSandbox — nil-safety and field mapping
// ---------------------------------------------------------------------------

func TestToSandbox_LabelsNeverNil(t *testing.T) {
	w := &wireSandbox{Name: "bare", Phase: "Ready"}
	// w.Labels is nil
	sb := toSandbox(w, "ns")
	assert.NotNil(t, sb.Labels, "Labels must never be nil even when wire has none")
}

func TestToSandbox_AnnotationsAlwaysEmptyMap(t *testing.T) {
	w := &wireSandbox{
		Name:   "bare",
		Phase:  "Ready",
		Labels: map[string]string{"k": "v"},
	}
	sb := toSandbox(w, "ns")
	assert.NotNil(t, sb.Annotations, "Annotations must be an empty map, never nil")
	assert.Empty(t, sb.Annotations, "Annotations must be empty (CLI has no annotations)")
}

func TestToSandbox_LabelFieldsPopulated(t *testing.T) {
	w := &wireSandbox{
		ID:   "id1",
		Name: "my-sb",
		Labels: map[string]string{
			"nvidia-ida/owner":       "dave",
			"nvidia-ida/scope":       "read-write",
			"nvidia-ida/ttl-minutes": "90",
		},
		Phase:     "Provisioning",
		CreatedAt: "2026-06-16 08:00:00",
	}
	sb := toSandbox(w, "openshell")
	assert.Equal(t, "dave", sb.Owner)
	assert.Equal(t, "read-write", sb.Scope)
	assert.Equal(t, "90", sb.TTLMinutes)
	assert.Equal(t, "Provisioning", sb.Phase)
	assert.Equal(t, "2026-06-16 08:00:00", sb.CreatedAt)
	assert.Equal(t, "openshell", sb.Namespace)
	assert.Equal(t, "", sb.AccessHint)
	assert.Equal(t, "", sb.Selector)
}

// ---------------------------------------------------------------------------
// New — custom binary path
// ---------------------------------------------------------------------------

func TestNew_EmptyBin_DefaultsToOpenshell(t *testing.T) {
	cli := New("", GatewayConfig{}, "ns", &fakeRunner{})
	assert.Equal(t, "openshell", cli.bin)
}

func TestNew_CustomBin(t *testing.T) {
	cli := New("/usr/local/bin/openshell", GatewayConfig{}, "ns", &fakeRunner{})
	assert.Equal(t, "/usr/local/bin/openshell", cli.bin)
}
