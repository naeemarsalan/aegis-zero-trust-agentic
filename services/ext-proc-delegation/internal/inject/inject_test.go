package inject_test

import (
	"testing"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/inject"
)

func TestBuildRequestMutation_Shape(t *testing.T) {
	token := "eyJfake.token.here"
	resp := inject.BuildRequestMutation(token)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	mut := resp.GetHeaderMutation()
	if mut == nil {
		t.Fatal("expected header mutation")
	}

	setHeaders := mut.GetSetHeaders()
	if len(setHeaders) < 2 {
		t.Fatalf("expected at least 2 SetHeaders, got %d", len(setHeaders))
	}

	found := map[string]string{}
	for _, h := range setHeaders {
		found[h.GetHeader().GetKey()] = h.GetHeader().GetValue()
	}

	if v, ok := found["Authorization"]; !ok {
		t.Error("missing Authorization header")
	} else if v != "Bearer "+token {
		t.Errorf("Authorization=%q want %q", v, "Bearer "+token)
	}

	if v, ok := found["X-Delegated-By"]; !ok {
		t.Error("missing X-Delegated-By header")
	} else if v != "ext-proc" {
		t.Errorf("X-Delegated-By=%q want ext-proc", v)
	}
}

func TestStripResponse_RemoveList(t *testing.T) {
	resp := inject.StripResponse()
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	mut := resp.GetHeaderMutation()
	if mut == nil {
		t.Fatal("expected header mutation")
	}

	removes := mut.GetRemoveHeaders()
	if len(removes) == 0 {
		t.Fatal("expected RemoveHeaders to be non-empty")
	}

	// Verify known headers are in the strip list.
	expected := inject.HeadersToStrip()
	removeSet := make(map[string]bool, len(removes))
	for _, h := range removes {
		removeSet[h] = true
	}
	for _, want := range expected {
		if !removeSet[want] {
			t.Errorf("expected %q in RemoveHeaders strip list", want)
		}
	}
}

func TestBuildRequestMutation_EmptyToken(t *testing.T) {
	// Even with an empty token the mutation should be structurally valid.
	resp := inject.BuildRequestMutation("")
	if resp == nil {
		t.Fatal("expected non-nil response for empty token")
	}
	mut := resp.GetHeaderMutation()
	if mut == nil {
		t.Fatal("expected header mutation")
	}
	for _, h := range mut.GetSetHeaders() {
		if h.GetHeader().GetKey() == "Authorization" {
			if h.GetHeader().GetValue() != "Bearer " {
				t.Errorf("Authorization=%q want 'Bearer '", h.GetHeader().GetValue())
			}
		}
	}
}
