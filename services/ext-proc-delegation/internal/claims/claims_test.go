package claims_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/metadata"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/claims"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/jwks"
)

// stubVerifier is a test double for the JWKS verifier. It returns vt/err
// regardless of the token, recording the raw token it was asked to verify.
type stubVerifier struct {
	vt       *jwks.VerifiedToken
	err      error
	gotToken string
}

func (s *stubVerifier) Verify(_ context.Context, raw string) (*jwks.VerifiedToken, error) {
	s.gotToken = raw
	if s.err != nil {
		return nil, s.err
	}
	return s.vt, nil
}

func verified(sub, user, iss string, groups ...string) *jwks.VerifiedToken {
	return &jwks.VerifiedToken{
		Raw:               "verified-raw-token",
		Sub:               sub,
		PreferredUsername: user,
		Issuer:            iss,
		Groups:            groups,
	}
}

func TestFromContext_VerifiedToken(t *testing.T) {
	v := &stubVerifier{vt: verified("user-1", "alice", "https://kc/realms/agentic", "mcp-users")}
	id, err := claims.FromContext(context.Background(), "Bearer header.token.sig", v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Sub != "user-1" || id.PreferredUsername != "alice" {
		t.Errorf("identity not from verified token: %+v", id)
	}
	// Raw must be the VERIFIED token, never the header-copied one.
	if id.Raw != "verified-raw-token" {
		t.Errorf("Raw=%q want verified-raw-token (verified, not header-copied)", id.Raw)
	}
	if v.gotToken != "header.token.sig" {
		t.Errorf("verifier got %q; want the bearer token stripped of prefix", v.gotToken)
	}
}

func TestFromContext_MissingToken_Denies(t *testing.T) {
	v := &stubVerifier{vt: verified("u", "n", "i")}
	_, err := claims.FromContext(context.Background(), "", v)
	if err == nil {
		t.Fatal("expected error when no Authorization token present")
	}
	if !errors.Is(err, claims.ErrNoToken) {
		t.Errorf("want ErrNoToken, got %v", err)
	}
}

func TestFromContext_NotBearer_Denies(t *testing.T) {
	v := &stubVerifier{vt: verified("u", "n", "i")}
	_, err := claims.FromContext(context.Background(), "Basic abc", v)
	if !errors.Is(err, claims.ErrNoToken) {
		t.Errorf("want ErrNoToken for non-Bearer scheme, got %v", err)
	}
}

func TestFromContext_VerificationFails_Denies(t *testing.T) {
	v := &stubVerifier{err: errors.New("bad signature")}
	_, err := claims.FromContext(context.Background(), "Bearer x.y.z", v)
	if err == nil {
		t.Fatal("expected error when verification fails")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFromContext_NilVerifier_FailsClosed(t *testing.T) {
	_, err := claims.FromContext(context.Background(), "Bearer x.y.z", nil)
	if err == nil {
		t.Fatal("expected fail-closed error when verifier is nil")
	}
}

func TestFromContext_MetadataAgrees(t *testing.T) {
	v := &stubVerifier{vt: verified("user-1", "alice", "https://kc/realms/agentic")}
	meta := `{"claims":{"sub":"user-1","preferred_username":"alice","iss":"https://kc/realms/agentic"}}`
	md := metadata.Pairs("dev.agentgateway.jwt", meta)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	id, err := claims.FromContext(ctx, "Bearer x.y.z", v)
	if err != nil {
		t.Fatalf("expected agreement to pass: %v", err)
	}
	if id.Sub != "user-1" {
		t.Errorf("Sub=%q want user-1", id.Sub)
	}
}

func TestFromContext_MetadataSubMismatch_Denies(t *testing.T) {
	// Verified token says user-1, but gateway metadata claims attacker.
	v := &stubVerifier{vt: verified("user-1", "alice", "https://kc/realms/agentic")}
	meta := `{"claims":{"sub":"attacker","preferred_username":"alice"}}`
	md := metadata.Pairs("dev.agentgateway.jwt", meta)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := claims.FromContext(ctx, "Bearer x.y.z", v)
	if err == nil {
		t.Fatal("expected deny on metadata-vs-token sub mismatch")
	}
	if !errors.Is(err, claims.ErrMetadataMismatch) {
		t.Errorf("want ErrMetadataMismatch, got %v", err)
	}
}

func TestFromContext_MetadataIssuerMismatch_Denies(t *testing.T) {
	v := &stubVerifier{vt: verified("user-1", "alice", "https://kc/realms/agentic")}
	meta := `{"claims":{"sub":"user-1","iss":"https://evil/realms/agentic"}}`
	md := metadata.Pairs("dev.agentgateway.jwt", meta)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := claims.FromContext(ctx, "Bearer x.y.z", v)
	if !errors.Is(err, claims.ErrMetadataMismatch) {
		t.Errorf("want ErrMetadataMismatch on issuer mismatch, got %v", err)
	}
}

func TestFromContext_MetadataUnparseable_Denies(t *testing.T) {
	// Metadata present but malformed: we cannot confirm agreement -> fail closed.
	v := &stubVerifier{vt: verified("user-1", "alice", "https://kc/realms/agentic")}
	md := metadata.Pairs("dev.agentgateway.jwt", "not-json")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := claims.FromContext(ctx, "Bearer x.y.z", v)
	if !errors.Is(err, claims.ErrMetadataMismatch) {
		t.Errorf("want ErrMetadataMismatch on unparseable metadata, got %v", err)
	}
}

func TestFromContext_MetadataPartialSubset_Allowed(t *testing.T) {
	// Gateway forwards only a subset (sub) that agrees; absent fields are not a
	// disagreement.
	v := &stubVerifier{vt: verified("user-1", "alice", "https://kc/realms/agentic")}
	meta := `{"claims":{"sub":"user-1"}}`
	md := metadata.Pairs("dev.agentgateway.jwt", meta)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	if _, err := claims.FromContext(ctx, "Bearer x.y.z", v); err != nil {
		t.Fatalf("expected subset agreement to pass: %v", err)
	}
}

func TestFromMetadataValue(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantSub string
		wantErr bool
	}{
		{name: "valid", raw: `{"claims":{"sub":"s1","preferred_username":"u1"}}`, wantSub: "s1"},
		{name: "missing claims key", raw: `{"other":{}}`, wantErr: true},
		{name: "invalid json", raw: `{bad`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, err := claims.FromMetadataValue(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id.Sub != tc.wantSub {
				t.Errorf("Sub=%q want %q", id.Sub, tc.wantSub)
			}
		})
	}
}
