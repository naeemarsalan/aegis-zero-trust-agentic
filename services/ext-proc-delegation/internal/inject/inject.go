// Package inject builds ext_proc header mutations for credential delegation.
// It injects the downstream user token into upstream requests and strips
// credential-bearing headers from upstream responses.
package inject

import (
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

// credentialHeadersToStrip is the list of response headers that may carry
// credentials or session tokens and must be removed before forwarding to clients.
var credentialHeadersToStrip = []string{
	"authorization",
	"x-vault-token",
	"x-vault-aws-iam-server-id",
	"set-cookie",
	"x-auth-token",
	"x-session-token",
	// The agent's own JIT capability token. Stripped from upstream responses so a
	// downstream that echoes request headers cannot leak it for replay within its
	// remaining TTL (security review 2026-06-18, HIGH finding).
	"x-jit-session-jwt",
}

// BuildRequestMutation returns a CommonResponse that sets the Authorization
// header on the upstream request to "Bearer <userToken>" and marks the call
// as delegated via X-Delegated-By.
func BuildRequestMutation(userToken string) *extprocv3.CommonResponse {
	return &extprocv3.CommonResponse{
		HeaderMutation: &extprocv3.HeaderMutation{
			SetHeaders: []*corev3.HeaderValueOption{
				{
					Header: &corev3.HeaderValue{
						Key:   "Authorization",
						Value: "Bearer " + userToken,
					},
					KeepEmptyValue: false,
				},
				{
					Header: &corev3.HeaderValue{
						Key:   "X-Delegated-By",
						Value: "ext-proc",
					},
					KeepEmptyValue: false,
				},
			},
		},
	}
}

// StripResponse returns a CommonResponse that removes credential-bearing headers
// from the upstream response before it reaches the downstream client.
func StripResponse() *extprocv3.CommonResponse {
	removeHeaders := make([]string, len(credentialHeadersToStrip))
	copy(removeHeaders, credentialHeadersToStrip)

	return &extprocv3.CommonResponse{
		HeaderMutation: &extprocv3.HeaderMutation{
			RemoveHeaders: removeHeaders,
		},
	}
}

// HeadersToStrip returns the list of credential headers that will be stripped.
// Exposed for testing.
func HeadersToStrip() []string {
	out := make([]string, len(credentialHeadersToStrip))
	copy(out, credentialHeadersToStrip)
	return out
}
