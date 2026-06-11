// Package claims derives the trusted caller identity that drives downstream
// token exchange.
//
// SECURITY MODEL — DEFENSE IN DEPTH (do not weaken):
//
// ext-proc does NOT trust that the agentgateway already validated the
// Authorization token. It INDEPENDENTLY VERIFIES the incoming Authorization
// Bearer JWT against the Keycloak JWKS (RS256 signature, issuer, audience,
// exp/nbf) via the jwks.Verifier before any claim is used. The verified token
// — never a header-copied or metadata-derived one — is what becomes
// Identity.Raw (the subject_token exchanged at Keycloak and ultimately injected
// downstream as the USER identity).
//
// The gateway-forwarded "dev.agentgateway.jwt" metadata (when present) is
// parsed only as a CROSS-CHECK: if the gateway's claims disagree with the
// independently verified token (e.g. a different sub), we FAIL CLOSED rather
// than trust either source. This prevents a compromised/misconfigured upstream
// hop, a smuggled Authorization header, or a forwarded client-supplied header
// from minting a downstream user token for an attacker-chosen subject.
//
// If there is no verifiable token, identity derivation FAILS (the caller denies
// with 401). There is no unverified fallback path.
package claims

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/metadata"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/jwks"
)

// Identity carries the normalized, VERIFIED user identity.
type Identity struct {
	Sub               string
	PreferredUsername string
	Groups            []string
	Issuer            string
	// Raw is the original VERIFIED JWT string (the downstream exchange subject_token).
	Raw string
}

// Verifier is the JWKS-backed token verifier dependency. Implemented by
// *jwks.Verifier; an interface here keeps claims testable.
type Verifier interface {
	Verify(ctx context.Context, raw string) (*jwks.VerifiedToken, error)
}

// agentGatewayMeta is the shape of the dev.agentgateway.jwt metadata value.
type agentGatewayMeta struct {
	Claims map[string]interface{} `json:"claims"`
}

// ErrNoToken is returned when no Authorization Bearer token is present to verify.
var ErrNoToken = errors.New("no verifiable token: Authorization Bearer header absent or malformed")

// ErrMetadataMismatch is returned when the gateway-forwarded claims disagree
// with the independently verified token. This is a fail-closed condition.
var ErrMetadataMismatch = errors.New("gateway-forwarded claims disagree with verified token")

// FromContext derives a VERIFIED Identity from the ext_proc stream.
//
// It (1) cryptographically verifies the Authorization Bearer JWT against the
// Keycloak JWKS, then (2) if dev.agentgateway.jwt metadata is present,
// cross-checks the gateway's claims against the verified token and fails closed
// on disagreement. The returned Identity.Raw is always the verified token.
func FromContext(ctx context.Context, authHeader string, v Verifier) (*Identity, error) {
	if v == nil {
		return nil, errors.New("claims: verifier is required (fail closed)")
	}

	rawToken, err := bearerToken(authHeader)
	if err != nil {
		return nil, err
	}

	verified, err := v.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	id := &Identity{
		Sub:               verified.Sub,
		PreferredUsername: verified.PreferredUsername,
		Groups:            verified.Groups,
		Issuer:            verified.Issuer,
		Raw:               verified.Raw, // VERIFIED token, not header-copied
	}

	// Cross-check against gateway-forwarded metadata, if present.
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		vals := md.Get("dev.agentgateway.jwt")
		if len(vals) > 0 && strings.TrimSpace(vals[0]) != "" {
			metaClaims, perr := parseAgentGatewayMeta(vals[0])
			if perr != nil {
				// Metadata present but unparseable: fail closed — we cannot
				// confirm it agrees with the verified token.
				return nil, fmt.Errorf("%w: unparseable metadata: %v", ErrMetadataMismatch, perr)
			}
			if mismatch := claimsDisagree(metaClaims, id); mismatch != "" {
				return nil, fmt.Errorf("%w: %s", ErrMetadataMismatch, mismatch)
			}
		}
	}

	return id, nil
}

// metaIdentity is the subset of gateway-forwarded claims we cross-check.
type metaIdentity struct {
	Sub               string
	PreferredUsername string
	Issuer            string
	Groups            []string
}

// claimsDisagree reports a human-readable reason if the gateway metadata
// contradicts the verified identity on any present field. An empty/absent
// metadata field is not a disagreement (the gateway may forward a subset).
func claimsDisagree(meta *metaIdentity, verified *Identity) string {
	if meta.Sub != "" && meta.Sub != verified.Sub {
		return fmt.Sprintf("sub mismatch (gateway=%q verified=%q)", meta.Sub, verified.Sub)
	}
	if meta.Issuer != "" && meta.Issuer != verified.Issuer {
		return fmt.Sprintf("iss mismatch (gateway=%q verified=%q)", meta.Issuer, verified.Issuer)
	}
	if meta.PreferredUsername != "" && meta.PreferredUsername != verified.PreferredUsername {
		return fmt.Sprintf("preferred_username mismatch (gateway=%q verified=%q)",
			meta.PreferredUsername, verified.PreferredUsername)
	}
	return ""
}

// bearerToken extracts the raw token from a "Bearer <token>" header value.
func bearerToken(header string) (string, error) {
	if header == "" {
		return "", ErrNoToken
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", ErrNoToken
	}
	tok := strings.TrimSpace(parts[1])
	if tok == "" {
		return "", ErrNoToken
	}
	return tok, nil
}

// FromMetadataValue parses identity from a raw dev.agentgateway.jwt JSON string.
// Exposed for testing the cross-check parsing only — these claims are NEVER
// used directly as identity.
func FromMetadataValue(raw string) (*metaIdentity, error) {
	return parseAgentGatewayMeta(raw)
}

// parseAgentGatewayMeta parses {"claims":{...}} into a cross-check identity.
func parseAgentGatewayMeta(raw string) (*metaIdentity, error) {
	var m agentGatewayMeta
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("dev.agentgateway.jwt unmarshal: %w", err)
	}
	if m.Claims == nil {
		return nil, errors.New("dev.agentgateway.jwt: missing claims object")
	}
	return claimsMapToMeta(m.Claims), nil
}

// claimsMapToMeta converts a free-form claims map to a metaIdentity.
func claimsMapToMeta(m map[string]interface{}) *metaIdentity {
	id := &metaIdentity{}
	if v, ok := m["sub"].(string); ok {
		id.Sub = v
	}
	if v, ok := m["preferred_username"].(string); ok {
		id.PreferredUsername = v
	}
	if v, ok := m["iss"].(string); ok {
		id.Issuer = v
	}
	switch g := m["groups"].(type) {
	case []interface{}:
		for _, item := range g {
			if s, ok := item.(string); ok {
				id.Groups = append(id.Groups, s)
			}
		}
	case []string:
		id.Groups = g
	}
	return id
}
