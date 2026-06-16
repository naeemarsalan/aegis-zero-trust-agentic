package extproc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/config"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/extproc"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/jwks"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/spire"
)

// --- stubs ---

type stubExchanger struct {
	tok string
	err error
}

func (s *stubExchanger) Exchange(_ context.Context, _, _ string) (string, error) {
	return s.tok, s.err
}

type stubVault struct {
	data      map[string]interface{}
	err       error
	grantData map[string]interface{}
	grantErr  error
}

func (s *stubVault) FetchToolSecret(_ context.Context, _ string) (map[string]interface{}, error) {
	return s.data, s.err
}

func (s *stubVault) FetchGrant(_ context.Context, _, _ string) (map[string]interface{}, error) {
	return s.grantData, s.grantErr
}

// stubVerifier returns a verified token (or an error) regardless of input.
type stubVerifier struct {
	vt  *jwks.VerifiedToken
	err error
}

func (s *stubVerifier) Verify(_ context.Context, _ string) (*jwks.VerifiedToken, error) {
	return s.vt, s.err
}

func okVerifier(sub string) *stubVerifier {
	return &stubVerifier{vt: &jwks.VerifiedToken{
		Raw:               "verified-subject-token",
		Sub:               sub,
		PreferredUsername: "alice",
		Issuer:            "https://kc/realms/agentic",
		Groups:            []string{"mcp-admins", "mcp-users"},
	}}
}

// --- helpers ---

func testConfig() *config.Config {
	return &config.Config{
		KeycloakTokenURL:     "http://keycloak",
		ExchangeMode:         config.ModeStandard,
		ExchangeClientID:     "cid",
		ExchangeSecretFile:   "/tmp/secret",
		DownstreamAudience:   "mcp-downstream",
		KeycloakJWKSURL:      "http://keycloak/jwks",
		KeycloakIssuer:       "https://kc/realms/agentic",
		ExpectedAudience:     "mcp-gateway",
		VaultAddr:            "http://vault",
		VaultJWTRole:         "ext-proc-delegation",
		VaultJWTAudience:     "vault",
		ToolSecretPathPrefix: "secret/data/mcp-tools/",
		ReadOnlyToolPrefixes:  []string{"get_", "list_", "search_"},
		DangerousToolPrefixes: []string{"add_", "set_", "delete_", "create_", "update_", "remove_"},
		RestrictedGroup:       "restricted",
		AdminGroup:            "mcp-admins",
		UserGroup:             "mcp-users",
		FailMode:             "closed",
		MaxBodyBytes:         262144,
		GRPCAddr:             ":9000",
		MetricsAddr:          ":9090",
	}
}

// startServer spins up an in-memory gRPC server and returns a connected client.
func startServer(t *testing.T, cfg *config.Config, kc extproc.Exchanger, v extproc.VaultClient, ver *stubVerifier) extprocv3.ExternalProcessorClient {
	t.Helper()
	srv := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(srv, extproc.NewServer(cfg, kc, v, ver, nil))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return extprocv3.NewExternalProcessorClient(conn)
}

func mcpBodyJSON(t *testing.T, tool string) []byte {
	t.Helper()
	body := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      tool,
			"arguments": map[string]interface{}{"host": "10.0.0.1"},
		},
	}
	b, _ := json.Marshal(body)
	return b
}

func headerMap(headers map[string]string) *corev3.HeaderMap {
	var hdrs []*corev3.HeaderValue
	for k, v := range headers {
		hdrs = append(hdrs, &corev3.HeaderValue{Key: k, Value: v})
	}
	return &corev3.HeaderMap{Headers: hdrs}
}

// --- tests ---

func TestProcess_HappyPath(t *testing.T) {
	cfg := testConfig()
	kc := &stubExchanger{tok: "downstream-token"}
	vlt := &stubVault{data: map[string]interface{}{"api_key": "k"}}

	client := startServer(t, cfg, kc, vlt, okVerifier("user-1"))
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	// 1. Send RequestHeaders.
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": "Bearer real.jwt.here",
					"x-jit-session": "session-abc",
				}),
			},
		},
	})
	if err != nil {
		t.Fatalf("send RequestHeaders: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv RequestHeaders ack: %v", err)
	}
	if _, ok := resp.Response.(*extprocv3.ProcessingResponse_RequestHeaders); !ok {
		t.Fatalf("expected RequestHeaders response, got %T", resp.Response)
	}

	// 2. Send RequestBody.
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        mcpBodyJSON(t, "list-routes"),
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("send RequestBody: %v", err)
	}

	resp, err = stream.Recv()
	if err != nil {
		t.Fatalf("recv RequestBody response: %v", err)
	}
	bodyResp, ok := resp.Response.(*extprocv3.ProcessingResponse_RequestBody)
	if !ok {
		t.Fatalf("expected RequestBody response, got %T", resp.Response)
	}
	mut := bodyResp.RequestBody.GetResponse().GetHeaderMutation()
	if mut == nil {
		t.Fatal("expected header mutation in body response")
	}
	var injected bool
	for _, h := range mut.GetSetHeaders() {
		if h.GetHeader().GetKey() == "Authorization" {
			injected = true
			if h.GetHeader().GetValue() != "Bearer downstream-token" {
				t.Errorf("Authorization=%q want Bearer downstream-token", h.GetHeader().GetValue())
			}
		}
	}
	if !injected {
		t.Error("Authorization header not injected")
	}

	// 3. Send ResponseHeaders.
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": "Bearer upstream-token",
					"content-type":  "application/json",
				}),
			},
		},
	})
	if err != nil {
		t.Fatalf("send ResponseHeaders: %v", err)
	}

	resp, err = stream.Recv()
	if err != nil {
		t.Fatalf("recv ResponseHeaders response: %v", err)
	}
	respHdrs, ok := resp.Response.(*extprocv3.ProcessingResponse_ResponseHeaders)
	if !ok {
		t.Fatalf("expected ResponseHeaders response, got %T", resp.Response)
	}
	removeHdrs := respHdrs.ResponseHeaders.GetResponse().GetHeaderMutation().GetRemoveHeaders()
	if len(removeHdrs) == 0 {
		t.Error("expected credential headers to be stripped from response")
	}

	_ = stream.CloseSend()
}

func TestProcess_IdentityMissing_401(t *testing.T) {
	cfg := testConfig()
	kc := &stubExchanger{tok: "tok"}
	v := &stubVault{data: map[string]interface{}{}}

	client := startServer(t, cfg, kc, v, okVerifier("u1"))
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	// Send RequestHeaders with no auth.
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"content-type": "application/json",
				}),
			},
		},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}

	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse for missing identity, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Unauthorized {
		t.Errorf("expected 401 Unauthorized, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}

	_ = stream.CloseSend()
}

// TestProcess_BadToken_401 covers a present-but-unverifiable token (bad
// signature, wrong issuer/aud, expired) — the verifier rejects it and ext-proc
// denies with 401 rather than trusting any header claim.
func TestProcess_BadToken_401(t *testing.T) {
	cfg := testConfig()
	kc := &stubExchanger{tok: "tok"}
	v := &stubVault{data: map[string]interface{}{}}
	badVer := &stubVerifier{err: errors.New("bad signature")}

	client := startServer(t, cfg, kc, v, badVer)
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": "Bearer forged.token.sig",
				}),
			},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse for unverifiable token, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Unauthorized {
		t.Errorf("expected 401 Unauthorized, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

// TestProcess_MetadataMismatch_Denies: verified token says user-1 but the
// gateway-forwarded metadata claims a different sub -> fail closed at headers.
func TestProcess_MetadataMismatch_Denies(t *testing.T) {
	cfg := testConfig()
	kc := &stubExchanger{tok: "downstream"}
	v := &stubVault{data: map[string]interface{}{}}

	client := startServer(t, cfg, kc, v, okVerifier("user-1"))

	md := metadata.Pairs("dev.agentgateway.jwt", `{"claims":{"sub":"attacker"}}`)
	ctx := metadata.NewOutgoingContext(context.Background(), md)
	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": "Bearer real.jwt.here",
				}),
			},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on metadata mismatch, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Unauthorized {
		t.Errorf("expected 401 on metadata mismatch, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

func TestProcess_KeycloakDown_403(t *testing.T) {
	cfg := testConfig()
	kc := &stubExchanger{err: context.DeadlineExceeded}
	v := &stubVault{data: map[string]interface{}{}}

	client := startServer(t, cfg, kc, v, okVerifier("u1"))
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": "Bearer real.jwt.here",
				}),
			},
		},
	})

	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers ack: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        mcpBodyJSON(t, "tool"),
				EndOfStream: true,
			},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv body response: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse (keycloak down), got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403 Forbidden, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}

	_ = stream.CloseSend()
}

// TestProcess_EmptyExchangeToken_Denies: exchange "succeeds" but returns an
// empty downstream token — must never inject/allow.
func TestProcess_EmptyExchangeToken_Denies(t *testing.T) {
	cfg := testConfig()
	kc := &stubExchanger{tok: ""} // empty downstream credential
	v := &stubVault{data: map[string]interface{}{}}

	client := startServer(t, cfg, kc, v, okVerifier("u1"))
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{"authorization": "Bearer real.jwt.here"}),
			},
		},
	})
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers ack: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{Body: mcpBodyJSON(t, "tool"), EndOfStream: true},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv body response: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse for empty downstream token, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403 Forbidden, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

// TestProcess_HeadersThenResponse_NoBody_FailsClosed: the gateway jumps from
// RequestHeaders straight to ResponseHeaders with no body (body-less request).
// The exchange never ran, so ext-proc must FAIL CLOSED (403) rather than emit
// an allow with an empty downstream token.
func TestProcess_HeadersThenResponse_NoBody_FailsClosed(t *testing.T) {
	cfg := testConfig()
	kc := &stubExchanger{tok: "downstream-token"}
	v := &stubVault{data: map[string]interface{}{"api_key": "k"}}

	client := startServer(t, cfg, kc, v, okVerifier("user-1"))
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	// RequestHeaders.
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{"authorization": "Bearer real.jwt.here"}),
			},
		},
	})
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers ack: %v", err)
	}

	// Skip RequestBody entirely — straight to ResponseHeaders.
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{"content-type": "application/json"}),
			},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv response-headers response: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("FAIL OPEN: expected ImmediateResponse 403 on body-less request, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403 Forbidden on body-less request, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

// TestProcess_EmptyBody_FailsClosed: a zero-length RequestBody for an MCP call
// cannot be delegated and must deny.
func TestProcess_EmptyBody_FailsClosed(t *testing.T) {
	cfg := testConfig()
	kc := &stubExchanger{tok: "downstream-token"}
	v := &stubVault{data: map[string]interface{}{}}

	client := startServer(t, cfg, kc, v, okVerifier("user-1"))
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{"authorization": "Bearer real.jwt.here"}),
			},
		},
	})
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers ack: %v", err)
	}

	// Empty body.
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{Body: []byte{}, EndOfStream: true},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv body response: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse 403 on empty body, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403 Forbidden on empty body, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

// --- SPIRE / sandbox agent path stubs ---

// stubSpireVerifier returns fixed SVIDClaims (or an error) for any input.
type stubSpireVerifier struct {
	claims *spire.SVIDClaims
	err    error
}

func (s *stubSpireVerifier) VerifySVID(_ context.Context, _ string) (*spire.SVIDClaims, error) {
	return s.claims, s.err
}

// stubOnBehalfExchanger satisfies both Exchanger and OnBehalfExchanger.
type stubOnBehalfExchanger struct {
	tok string
	err error
}

func (s *stubOnBehalfExchanger) Exchange(_ context.Context, _, _ string) (string, error) {
	return s.tok, s.err
}

func (s *stubOnBehalfExchanger) ExchangeOnBehalf(_ context.Context, _, _ string) (string, error) {
	return s.tok, s.err
}

// testConfigWithSpire returns a config with a fake SPIRE issuer set (so
// IsSPIRESVID routing fires) and a sandbox grant path.
func testConfigWithSpire() *config.Config {
	cfg := testConfig()
	cfg.SpireJWKSURL = "http://spire-oidc/keys"
	cfg.SpireIssuer = "https://spire-oidc.apps.anaeem.na-launch.com"
	cfg.SpireAudience = "mcp-gateway"
	cfg.SandboxGrantPathPrefix = "secret/data/sandbox-grants/"
	// Static-auth path config required for the /mcp -> static token injection.
	cfg.StaticAuthPaths = []string{"/mcp"}
	cfg.StaticTokenSecret = "mcp-tokens"
	return cfg
}

// startServerWithSpire spins up a server with a SPIRE verifier stub.
func startServerWithSpire(
	t *testing.T,
	cfg *config.Config,
	kc *stubOnBehalfExchanger,
	vlt *stubVault,
	kcVer *stubVerifier,
	sv *stubSpireVerifier,
) extprocv3.ExternalProcessorClient {
	t.Helper()
	srv := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(srv,
		extproc.NewServerWithSpire(cfg, kc, vlt, kcVer, nil, sv))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return extprocv3.NewExternalProcessorClient(conn)
}

// startServerWithSpireJIT is startServerWithSpire plus a jit-approver session-JWT
// verifier (exercises the sandbox-agent JIT-elevation path).
func startServerWithSpireJIT(
	t *testing.T,
	cfg *config.Config,
	kc *stubOnBehalfExchanger,
	vlt *stubVault,
	kcVer *stubVerifier,
	sv *stubSpireVerifier,
	jit *stubVerifier,
) extprocv3.ExternalProcessorClient {
	t.Helper()
	srv := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(srv,
		extproc.NewServerWithSpire(cfg, kc, vlt, kcVer, jit, sv))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)
	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return extprocv3.NewExternalProcessorClient(conn)
}

// jitVerifier returns a stub JIT verifier yielding a session token bound to
// sandboxUID with the given tool_scope.
func jitVerifier(sandboxUID string, toolScope []string) *stubVerifier {
	return &stubVerifier{vt: &jwks.VerifiedToken{
		Raw:        "jit-session-jwt",
		Sub:        "jit-session-" + sandboxUID,
		Issuer:     "https://jit-approver",
		ToolScope:  toolScope,
		SandboxUID: sandboxUID,
	}}
}

// validGrantData returns a valid Vault grant data map for sandbox-uid/nonce.
func validGrantData(sandboxUID, nonce, user string) map[string]interface{} {
	return map[string]interface{}{
		"user":        user,
		"scope":       "read-only",
		"ttl":         float64(3600),
		"nonce":       nonce,
		"created":     time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339Nano),
		"sandbox_uid": sandboxUID,
		"version":     float64(1),
	}
}

// buildSpireBearerHeader builds an Authorization header value that will be
// detected as a SPIRE SVID by IsSPIRESVID (the payload encodes the issuer).
// The stub verifier ignores the actual cryptographic content.
func buildSpireBearerHeader(spireIssuer string) string {
	import64 := func(s string) string {
		// base64url-encode without padding for the JWT payload
		encoded := make([]byte, 0, len(s)*2)
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '+':
				encoded = append(encoded, '-')
			case '/':
				encoded = append(encoded, '_')
			default:
				encoded = append(encoded, s[i])
			}
		}
		return string(encoded)
	}
	// Build a fake JWT whose payload contains the iss claim.
	// header.payload.sig (stub verifier ignores sig).
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNwaXJlLWsxIn0"
	// Payload: {"iss":"<spireIssuer>","sub":"spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/agent","aud":["mcp-gateway"]}
	payloadJSON := `{"iss":"` + spireIssuer + `","sub":"spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/agent","aud":["mcp-gateway"],"exp":9999999999}`
	// base64url encode
	import64Str := import64(payloadJSON)
	_ = import64Str
	// Use encoding/base64 via direct import — build a proper base64url payload.
	return "Bearer " + header + "." + buildBase64URLPayload(payloadJSON) + ".stub-sig"
}

func buildBase64URLPayload(payload string) string {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	_ = base64Chars
	// Use encoding/base64 RawURL.
	b := []byte(payload)
	// Simple base64url encode.
	result := make([]byte, 0, (len(b)*4+2)/3)
	for i := 0; i < len(b); i += 3 {
		var b0, b1, b2 byte
		b0 = b[i]
		if i+1 < len(b) {
			b1 = b[i+1]
		}
		if i+2 < len(b) {
			b2 = b[i+2]
		}
		const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		result = append(result, chars[b0>>2])
		result = append(result, chars[((b0&3)<<4)|(b1>>4)])
		if i+1 < len(b) {
			result = append(result, chars[((b1&0xf)<<2)|(b2>>6)])
		}
		if i+2 < len(b) {
			result = append(result, chars[b2&0x3f])
		}
	}
	return string(result)
}

// --- SPIRE path tests ---

// TestProcess_SpirePath_HappyPath tests the full SPIRE path: valid SVID +
// valid grant + successful exchange + static token injected.
//
// The SVID sub path is spiffe://anaeem.na-launch.com/ns/openshell/sandbox/<uuid>.
// SandboxUID is parsed from the path by VerifySVID; no nonce is present in the
// SVID (real SPIRE JWT-SVIDs cannot carry custom claims).
func TestProcess_SpirePath_HappyPath(t *testing.T) {
	cfg := testConfigWithSpire()
	const sandboxUID = "uid-abc-123"
	const user = "arsalan"

	kc := &stubOnBehalfExchanger{tok: "exchanged-downstream-token"}
	vlt := &stubVault{
		// FetchGrant returns valid grant data (nonce in grant is vestigial/audit-only).
		grantData: validGrantData(sandboxUID, "vestigial-nonce", user),
		// FetchToolSecret (for static tokens) returns the user's pfSense token.
		data: map[string]interface{}{user: "pfsense-static-token"},
	}
	sv := &stubSpireVerifier{
		claims: &spire.SVIDClaims{
			SpiffeID:   "spiffe://anaeem.na-launch.com/ns/openshell/sandbox/" + sandboxUID,
			SandboxUID: sandboxUID, // parsed from sub path; no SandboxNonce
		},
	}

	client := startServerWithSpire(t, cfg, kc, vlt, okVerifier("ignored"), sv)
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	// 1. Send RequestHeaders with a fake SPIRE bearer.
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": buildSpireBearerHeader(cfg.SpireIssuer),
					":path":         "/mcp",
				}),
			},
		},
	})
	if err != nil {
		t.Fatalf("send RequestHeaders: %v", err)
	}
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers ack: %v", err)
	}

	// 2. Send RequestBody.
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        mcpBodyJSON(t, "search_firewall_rules"),
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("send RequestBody: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv RequestBody response: %v", err)
	}
	bodyResp, ok := resp.Response.(*extprocv3.ProcessingResponse_RequestBody)
	if !ok {
		t.Fatalf("expected RequestBody response, got %T", resp.Response)
	}
	mut := bodyResp.RequestBody.GetResponse().GetHeaderMutation()
	if mut == nil {
		t.Fatal("expected header mutation")
	}
	var injectedToken string
	for _, h := range mut.GetSetHeaders() {
		if h.GetHeader().GetKey() == "Authorization" {
			injectedToken = h.GetHeader().GetValue()
		}
	}
	// The static token (pfsense-static-token) should be injected, NOT the agent SVID.
	if injectedToken != "Bearer pfsense-static-token" {
		t.Errorf("injected=%q want Bearer pfsense-static-token", injectedToken)
	}

	_ = stream.CloseSend()
}

// TestProcess_SpirePath_SVIDInvalid_Deny ensures an invalid SVID -> 401.
func TestProcess_SpirePath_SVIDInvalid_Deny(t *testing.T) {
	cfg := testConfigWithSpire()
	kc := &stubOnBehalfExchanger{tok: "tok"}
	vlt := &stubVault{}
	sv := &stubSpireVerifier{err: errors.New("bad signature")}

	client := startServerWithSpire(t, cfg, kc, vlt, okVerifier("u"), sv)
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": buildSpireBearerHeader(cfg.SpireIssuer),
				}),
			},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse for bad SVID, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Unauthorized {
		t.Errorf("expected 401, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

// TestProcess_SpirePath_GrantAbsent_Deny ensures a 404 grant -> 403.
func TestProcess_SpirePath_GrantAbsent_Deny(t *testing.T) {
	cfg := testConfigWithSpire()
	kc := &stubOnBehalfExchanger{tok: "tok"}
	vlt := &stubVault{grantData: nil, grantErr: nil} // nil = 404
	sv := &stubSpireVerifier{
		claims: &spire.SVIDClaims{
			SpiffeID:   "spiffe://anaeem.na-launch.com/ns/openshell/sandbox/uid-missing",
			SandboxUID: "uid-missing",
		},
	}

	client := startServerWithSpire(t, cfg, kc, vlt, okVerifier("u"), sv)
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": buildSpireBearerHeader(cfg.SpireIssuer),
				}),
			},
		},
	})
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body: mcpBodyJSON(t, "search_firewall_rules"), EndOfStream: true,
			},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv body: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse for absent grant, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

// TestProcess_SpirePath_UIDMismatch_Deny ensures that when the grant's
// sandbox_uid field does not match the UUID from the SVID sub path, the
// request is denied with 403.
//
// This replaces the old nonce-mismatch test. Real SPIRE JWT-SVIDs carry no
// nonce custom claim; the binding is the cryptographic sandbox UUID in the
// SPIFFE URI. The grant's sandbox_uid field must equal svidClaims.SandboxUID
// (parsed from sub); a mismatch means the Vault document was written for a
// different sandbox.
func TestProcess_SpirePath_UIDMismatch_Deny(t *testing.T) {
	cfg := testConfigWithSpire()
	const svidUID = "uid-from-svid-path"
	const grantUID = "uid-DIFFERENT-in-grant" // mismatch
	kc := &stubOnBehalfExchanger{tok: "tok"}
	vlt := &stubVault{
		// Grant document records a different sandbox_uid than the SVID provides.
		grantData: validGrantData(grantUID, "any-nonce", "arsalan"),
	}
	sv := &stubSpireVerifier{
		claims: &spire.SVIDClaims{
			SpiffeID:   "spiffe://anaeem.na-launch.com/ns/openshell/sandbox/" + svidUID,
			SandboxUID: svidUID, // parsed from sub path by VerifySVID
		},
	}

	client := startServerWithSpire(t, cfg, kc, vlt, okVerifier("u"), sv)
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": buildSpireBearerHeader(cfg.SpireIssuer),
				}),
			},
		},
	})
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body: mcpBodyJSON(t, "search_firewall_rules"), EndOfStream: true,
			},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv body: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse for UID mismatch, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

// TestProcess_SpirePath_GrantExpired_Deny ensures an expired grant -> 403.
func TestProcess_SpirePath_GrantExpired_Deny(t *testing.T) {
	cfg := testConfigWithSpire()
	const sandboxUID = "uid-abc-123"
	kc := &stubOnBehalfExchanger{tok: "tok"}
	// Build a grant that expired 1 hour ago (TTL=60s, created 2h ago).
	expiredGrant := map[string]interface{}{
		"user":        "arsalan",
		"scope":       "read-only",
		"ttl":         float64(60),
		"nonce":       "vestigial-nonce", // retained in grant for audit; not matched from SVID
		"created":     time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339Nano),
		"sandbox_uid": sandboxUID,
		"version":     float64(1),
	}
	vlt := &stubVault{grantData: expiredGrant}
	sv := &stubSpireVerifier{
		claims: &spire.SVIDClaims{
			SpiffeID:   "spiffe://anaeem.na-launch.com/ns/openshell/sandbox/" + sandboxUID,
			SandboxUID: sandboxUID,
		},
	}

	client := startServerWithSpire(t, cfg, kc, vlt, okVerifier("u"), sv)
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": buildSpireBearerHeader(cfg.SpireIssuer),
				}),
			},
		},
	})
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body: mcpBodyJSON(t, "search_firewall_rules"), EndOfStream: true,
			},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv body: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse for expired grant, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

// TestProcess_SpirePath_ScopeDenied_Deny ensures a write tool under a
// read-only grant is denied.
func TestProcess_SpirePath_ScopeDenied_Deny(t *testing.T) {
	cfg := testConfigWithSpire()
	const sandboxUID = "uid-abc-123"
	kc := &stubOnBehalfExchanger{tok: "tok"}
	vlt := &stubVault{grantData: validGrantData(sandboxUID, "any-nonce", "arsalan")}
	sv := &stubSpireVerifier{
		claims: &spire.SVIDClaims{
			SpiffeID:   "spiffe://anaeem.na-launch.com/ns/openshell/sandbox/" + sandboxUID,
			SandboxUID: sandboxUID,
		},
	}

	client := startServerWithSpire(t, cfg, kc, vlt, okVerifier("u"), sv)
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": buildSpireBearerHeader(cfg.SpireIssuer),
				}),
			},
		},
	})
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers: %v", err)
	}

	// delete_ is a write/dangerous tool — should be denied under read-only grant.
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body: mcpBodyJSON(t, "delete_firewall_rule"), EndOfStream: true,
			},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv body: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse for scope denied, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

// TestProcess_SpirePath_ExchangeFails_Deny ensures on-behalf exchange failure -> 403.
func TestProcess_SpirePath_ExchangeFails_Deny(t *testing.T) {
	cfg := testConfigWithSpire()
	const sandboxUID = "uid-abc-123"
	kc := &stubOnBehalfExchanger{err: errors.New("keycloak unavailable")}
	vlt := &stubVault{grantData: validGrantData(sandboxUID, "any-nonce", "arsalan")}
	sv := &stubSpireVerifier{
		claims: &spire.SVIDClaims{
			SpiffeID:   "spiffe://anaeem.na-launch.com/ns/openshell/sandbox/" + sandboxUID,
			SandboxUID: sandboxUID,
		},
	}

	client := startServerWithSpire(t, cfg, kc, vlt, okVerifier("u"), sv)
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": buildSpireBearerHeader(cfg.SpireIssuer),
				}),
			},
		},
	})
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body: mcpBodyJSON(t, "search_firewall_rules"), EndOfStream: true,
			},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv body: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse for exchange failure, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

// TestProcess_SpirePath_StaticPath_ExchangeFails_AllowsStaticToken verifies the
// non-fatal-exchange behaviour on the /mcp static-auth path: when the RFC 8693
// on-behalf exchange fails, delegation STILL succeeds by injecting the per-user
// pre-provisioned static token (the exchanged JWT was never the credential on
// this path — it is audit-only). Contrast with TestProcess_SpirePath_
// ExchangeFails_Deny, which has no :path (non-static, JWT-downstream) and so
// stays fail-closed.
func TestProcess_SpirePath_StaticPath_ExchangeFails_AllowsStaticToken(t *testing.T) {
	cfg := testConfigWithSpire()
	const sandboxUID = "uid-abc-123"
	const user = "arsalan"

	// Exchange fails (simulating the Keycloak 26.6.3 v1 token-exchange NPE).
	kc := &stubOnBehalfExchanger{err: errors.New("keycloak exchange: HTTP 500")}
	vlt := &stubVault{
		grantData: validGrantData(sandboxUID, "vestigial-nonce", user),
		data:      map[string]interface{}{user: "pfsense-static-token"},
	}
	sv := &stubSpireVerifier{
		claims: &spire.SVIDClaims{
			SpiffeID:   "spiffe://anaeem.na-launch.com/ns/openshell/sandbox/" + sandboxUID,
			SandboxUID: sandboxUID,
		},
	}

	client := startServerWithSpire(t, cfg, kc, vlt, okVerifier("ignored"), sv)
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	// RequestHeaders with the /mcp (static-auth) path.
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": buildSpireBearerHeader(cfg.SpireIssuer),
					":path":         "/mcp",
				}),
			},
		},
	})
	if err != nil {
		t.Fatalf("send RequestHeaders: %v", err)
	}
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers ack: %v", err)
	}

	// RequestBody — a read-only tool call.
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        mcpBodyJSON(t, "search_firewall_rules"),
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("send RequestBody: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv RequestBody response: %v", err)
	}
	// Must be an allow (body mutation), NOT an ImmediateResponse deny.
	if imm, isImm := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse); isImm {
		t.Fatalf("expected allow with static token, got deny %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	bodyResp, ok := resp.Response.(*extprocv3.ProcessingResponse_RequestBody)
	if !ok {
		t.Fatalf("expected RequestBody response, got %T", resp.Response)
	}
	mut := bodyResp.RequestBody.GetResponse().GetHeaderMutation()
	if mut == nil {
		t.Fatal("expected header mutation")
	}
	var injectedToken string
	for _, h := range mut.GetSetHeaders() {
		if h.GetHeader().GetKey() == "Authorization" {
			injectedToken = h.GetHeader().GetValue()
		}
	}
	// The per-user static token is injected despite the exchange failure.
	if injectedToken != "Bearer pfsense-static-token" {
		t.Errorf("injected=%q want Bearer pfsense-static-token (static token injected despite exchange failure)", injectedToken)
	}

	_ = stream.CloseSend()
}

// runSpireJITToolCall drives the SVID + x-jit-session-jwt flow on /mcp for the
// given tool and returns the RequestBody-phase response (allow mutation or deny).
func runSpireJITToolCall(t *testing.T, client extprocv3.ExternalProcessorClient, cfg *config.Config, tool string) *extprocv3.ProcessingResponse {
	t.Helper()
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization":     buildSpireBearerHeader(cfg.SpireIssuer),
					":path":             "/mcp",
					"x-jit-session-jwt": "jit.session.jwt",
				}),
			},
		},
	}); err != nil {
		t.Fatalf("send headers: %v", err)
	}
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers ack: %v", err)
	}
	if err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{Body: mcpBodyJSON(t, tool), EndOfStream: true},
		},
	}); err != nil {
		t.Fatalf("send body: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv body: %v", err)
	}
	_ = stream.CloseSend()
	return resp
}

func spireJITFixtures(uid string) (*stubOnBehalfExchanger, *stubVault, *stubSpireVerifier) {
	return &stubOnBehalfExchanger{tok: "exchanged"},
		&stubVault{
			grantData: validGrantData(uid, "nonce", "arsalan"),
			data:      map[string]interface{}{"arsalan": "pfsense-static-token"},
		},
		&stubSpireVerifier{claims: &spire.SVIDClaims{
			SpiffeID:   "spiffe://anaeem.na-launch.com/ns/agent-sandbox/sandbox/" + uid,
			SandboxUID: uid,
		}}
}

// TestProcess_SpirePath_JITBoundElevation_Allows: a dangerous tool denied under
// the read-only grant is ALLOWED when a sandbox-bound JIT session JWT whose
// tool_scope covers it is presented — proving JIT escalation on the delegated
// SVID path. The per-user static token is still the injected credential.
func TestProcess_SpirePath_JITBoundElevation_Allows(t *testing.T) {
	cfg := testConfigWithSpire()
	const uid = "uid-abc-123"
	const tool = "create_firewall_rule_advanced"
	kc, vlt, sv := spireJITFixtures(uid)
	jit := jitVerifier(uid, []string{tool}) // bound to THIS sandbox + covers the tool
	client := startServerWithSpireJIT(t, cfg, kc, vlt, okVerifier("ignored"), sv, jit)

	resp := runSpireJITToolCall(t, client, cfg, tool)
	if imm, isImm := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse); isImm {
		t.Fatalf("expected JIT-elevated allow, got deny %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	br, ok := resp.Response.(*extprocv3.ProcessingResponse_RequestBody)
	if !ok {
		t.Fatalf("expected RequestBody response, got %T", resp.Response)
	}
	var injected string
	for _, h := range br.RequestBody.GetResponse().GetHeaderMutation().GetSetHeaders() {
		if h.GetHeader().GetKey() == "Authorization" {
			injected = h.GetHeader().GetValue()
		}
	}
	if injected != "Bearer pfsense-static-token" {
		t.Errorf("injected=%q want Bearer pfsense-static-token", injected)
	}
}

// TestProcess_SpirePath_JITSandboxMismatch_Denies: a JIT session JWT bound to a
// DIFFERENT sandbox must NOT elevate this one (fail-closed cross-sandbox binding).
func TestProcess_SpirePath_JITSandboxMismatch_Denies(t *testing.T) {
	cfg := testConfigWithSpire()
	const uid = "uid-abc-123"
	const tool = "create_firewall_rule_advanced"
	kc, vlt, sv := spireJITFixtures(uid)
	jit := jitVerifier("a-different-sandbox-uid", []string{tool}) // bound elsewhere
	client := startServerWithSpireJIT(t, cfg, kc, vlt, okVerifier("ignored"), sv, jit)

	resp := runSpireJITToolCall(t, client, cfg, tool)
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected deny for cross-sandbox JIT JWT, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
}

// TestProcess_SpirePath_JITToolNotInScope_Denies: a sandbox-bound JIT session
// JWT that does not list the requested tool must NOT elevate it.
func TestProcess_SpirePath_JITToolNotInScope_Denies(t *testing.T) {
	cfg := testConfigWithSpire()
	const uid = "uid-abc-123"
	const tool = "create_firewall_rule_advanced"
	kc, vlt, sv := spireJITFixtures(uid)
	jit := jitVerifier(uid, []string{"some_other_tool"}) // bound but wrong tool
	client := startServerWithSpireJIT(t, cfg, kc, vlt, okVerifier("ignored"), sv, jit)

	resp := runSpireJITToolCall(t, client, cfg, tool)
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected deny when tool not in JIT scope, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
}

// TestProcess_SpirePath_JITEmptySandboxUID_Denies: a session JWT with an EMPTY
// sandbox_uid claim carries no binding and must NOT elevate (fail-closed).
func TestProcess_SpirePath_JITEmptySandboxUID_Denies(t *testing.T) {
	cfg := testConfigWithSpire()
	const uid = "uid-abc-123"
	const tool = "create_firewall_rule_advanced"
	kc, vlt, sv := spireJITFixtures(uid)
	jit := jitVerifier("", []string{tool}) // unbound (empty sandbox_uid)
	client := startServerWithSpireJIT(t, cfg, kc, vlt, okVerifier("ignored"), sv, jit)

	resp := runSpireJITToolCall(t, client, cfg, tool)
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected deny for empty-sandbox_uid JIT JWT, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
}

// TestProcess_SpirePath_MissingSandboxUID_Deny: SVID missing sandbox_uid -> 401.
// Finding 6: VerifySVID now fails closed at the verification step itself when
// sandbox_uid is empty, so the denial occurs at the RequestHeaders phase (401)
// rather than the RequestBody phase (403).
func TestProcess_SpirePath_MissingSandboxUID_Deny(t *testing.T) {
	cfg := testConfigWithSpire()
	kc := &stubOnBehalfExchanger{tok: "tok"}
	vlt := &stubVault{}
	// Finding 6: the stub verifier returns an error directly (as the real Verifier
	// now does) when sandbox_uid is missing.
	sv := &stubSpireVerifier{
		err: errors.New("spire svid: sandbox_uid claim is missing or empty"),
	}

	client := startServerWithSpire(t, cfg, kc, vlt, okVerifier("u"), sv)
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": buildSpireBearerHeader(cfg.SpireIssuer),
				}),
			},
		},
	})

	// Finding 6: the deny now fires at RequestHeaders (401 SVID invalid), not body.
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse for missing sandbox_uid (at headers), got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Unauthorized {
		t.Errorf("expected 401 Unauthorized for missing sandbox_uid (Finding 6), got %v",
			imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

func TestProcess_OversizedBody_Deny(t *testing.T) {
	cfg := testConfig()
	cfg.MaxBodyBytes = 10 // very small limit

	kc := &stubExchanger{tok: "tok"}
	v := &stubVault{data: map[string]interface{}{}}

	client := startServer(t, cfg, kc, v, okVerifier("u1"))
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{"authorization": "Bearer real.jwt.here"}),
			},
		},
	})

	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers ack: %v", err)
	}

	bigBody := make([]byte, 100)
	for i := range bigBody {
		bigBody[i] = 'x'
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{Body: bigBody, EndOfStream: true},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv body response: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse for oversized body, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_PayloadTooLarge {
		t.Errorf("expected 413 PayloadTooLarge, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}

	_ = stream.CloseSend()
}

// ---------------------------------------------------------------------------
// Finding 1: audit result fields must be safe enum codes, never raw error text
// ---------------------------------------------------------------------------

// TestProcess_KeycloakDown_AuditResultIsCode verifies that when the Keycloak
// exchange fails the emitted keycloak_result is a safe enum code (not raw error).
// We can only observe this indirectly (the handler still returns 403); the test
// asserts the 403 body is the safe reason string (not raw error text).
func TestProcess_KeycloakDown_AuditResultIsCode(t *testing.T) {
	cfg := testConfig()
	// Inject an error whose message would be toxic if logged raw.
	kc := &stubExchanger{err: errors.New("X-Vault-Token: hvs.secret dial tcp 10.0.0.1:443")}
	v := &stubVault{data: map[string]interface{}{}}

	client := startServer(t, cfg, kc, v, okVerifier("u1"))
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{"authorization": "Bearer real.jwt.here"}),
			},
		},
	})
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers ack: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        mcpBodyJSON(t, "tool"),
				EndOfStream: true,
			},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv body response: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", resp.Response)
	}
	// The 403 body is the safe reason string — never the raw error.
	body := string(imm.ImmediateResponse.GetBody())
	if body == "X-Vault-Token: hvs.secret dial tcp 10.0.0.1:443" {
		t.Error("raw exchange error text must not appear in the response body (info-leak)")
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

// ---------------------------------------------------------------------------
// Finding 3: grant TTL cap enforced in ext-proc
// ---------------------------------------------------------------------------

// TestProcess_SpirePath_GrantTTLExceedsCap_Deny ensures a grant whose TTL
// field exceeds MaxGrantTTLSeconds is rejected with 403.
func TestProcess_SpirePath_GrantTTLExceedsCap_Deny(t *testing.T) {
	cfg := testConfigWithSpire()
	const sandboxUID = "uid-abc-123"
	kc := &stubOnBehalfExchanger{tok: "tok"}

	// Build a grant with TTL well above the cap (e.g. 86400 = 24h).
	oversizedGrant := map[string]interface{}{
		"user":        "arsalan",
		"scope":       "read-only",
		"ttl":         float64(86400), // 24h > 3600s cap
		"nonce":       "vestigial-nonce",
		"created":     time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339Nano),
		"sandbox_uid": sandboxUID,
		"version":     float64(1),
	}
	vlt := &stubVault{grantData: oversizedGrant}
	sv := &stubSpireVerifier{
		claims: &spire.SVIDClaims{
			SpiffeID:   "spiffe://anaeem.na-launch.com/ns/openshell/sandbox/" + sandboxUID,
			SandboxUID: sandboxUID,
		},
	}

	client := startServerWithSpire(t, cfg, kc, vlt, okVerifier("u"), sv)
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": buildSpireBearerHeader(cfg.SpireIssuer),
				}),
			},
		},
	})
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body: mcpBodyJSON(t, "search_firewall_rules"), EndOfStream: true,
			},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv body: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse for TTL cap exceeded, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403 for TTL cap exceeded, got %v", imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

// ---------------------------------------------------------------------------
// Finding 4: privileged group check on on-behalf-exchange result
// ---------------------------------------------------------------------------

// stubOnBehalfExchangerWithGroups returns a JWT payload embedding a groups claim.
// We embed the privileged group directly in a fake JWT payload (base64url) to
// simulate the scenario where Keycloak minted a token for a privileged user.
type stubPrivilegedExchanger struct{}

func (s *stubPrivilegedExchanger) Exchange(_ context.Context, _, _ string) (string, error) {
	return "tok", nil
}

func (s *stubPrivilegedExchanger) ExchangeOnBehalf(_ context.Context, _, _ string) (string, error) {
	// Build a fake JWT whose payload contains groups=["mcp-admins"].
	import64 := func(s string) string {
		var b []byte
		for _, c := range []byte(s) {
			switch c {
			case '+':
				b = append(b, '-')
			case '/':
				b = append(b, '_')
			case '=':
				// skip padding
			default:
				b = append(b, c)
			}
		}
		return string(b)
	}
	payload := import64(
		"eyJzdWIiOiJhcnNhbGFuIiwiZ3JvdXBzIjpbIm1jcC1hZG1pbnMiXX0=",
	) // {"sub":"arsalan","groups":["mcp-admins"]}
	return "fake-hdr." + payload + ".fake-sig", nil
}

func TestProcess_SpirePath_PrivilegedGroupInExchangedToken_Deny(t *testing.T) {
	cfg := testConfigWithSpire()
	const sandboxUID = "uid-abc-123"
	kc := &stubPrivilegedExchanger{}
	vlt := &stubVault{
		grantData: validGrantData(sandboxUID, "any-nonce", "arsalan"),
		data:      map[string]interface{}{"arsalan": "pfsense-static-token"},
	}
	sv := &stubSpireVerifier{
		claims: &spire.SVIDClaims{
			SpiffeID:   "spiffe://anaeem.na-launch.com/ns/openshell/sandbox/" + sandboxUID,
			SandboxUID: sandboxUID,
		},
	}

	srv := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(srv,
		extproc.NewServerWithSpire(cfg, kc, vlt, okVerifier("ignored"), nil, sv))
	lis, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		t.Fatalf("listen: %v", lerr)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)
	conn, cerr := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if cerr != nil {
		t.Fatalf("dial: %v", cerr)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := extprocv3.NewExternalProcessorClient(conn)

	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": buildSpireBearerHeader(cfg.SpireIssuer),
					":path":         "/mcp",
				}),
			},
		},
	})
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body: mcpBodyJSON(t, "search_firewall_rules"), EndOfStream: true,
			},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv body: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse when privileged group detected, got %T", resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403 when impersonation target is privileged, got %v",
			imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}

// ---------------------------------------------------------------------------
// Finding 5: hard-pin sandbox-agent path to read-only
// ---------------------------------------------------------------------------

// TestProcess_SpirePath_AdminGrantHardPinnedToReadOnly ensures that even when a
// grant carries scope=admin, the sandbox-agent path only allows read-only tools
// (grantScopeGroups always returns mcp-users, not mcp-admins).
func TestProcess_SpirePath_AdminGrantHardPinnedToReadOnly(t *testing.T) {
	cfg := testConfigWithSpire()
	const sandboxUID = "uid-abc-123"
	kc := &stubOnBehalfExchanger{tok: "tok"}

	// Grant has scope=admin, but the dangerous delete tool should still be denied.
	adminGrant := map[string]interface{}{
		"user":        "arsalan",
		"scope":       "admin", // elevated — but hard-pinned to read-only in this slice
		"ttl":         float64(3600),
		"nonce":       "vestigial-nonce",
		"created":     time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339Nano),
		"sandbox_uid": sandboxUID,
		"version":     float64(1),
	}
	vlt := &stubVault{grantData: adminGrant}
	sv := &stubSpireVerifier{
		claims: &spire.SVIDClaims{
			SpiffeID:   "spiffe://anaeem.na-launch.com/ns/openshell/sandbox/" + sandboxUID,
			SandboxUID: sandboxUID,
		},
	}

	client := startServerWithSpire(t, cfg, kc, vlt, okVerifier("u"), sv)
	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(map[string]string{
					"authorization": buildSpireBearerHeader(cfg.SpireIssuer),
				}),
			},
		},
	})
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("recv headers: %v", err)
	}

	// A dangerous (delete_) tool must be denied even under admin grant scope.
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body: mcpBodyJSON(t, "delete_firewall_rule"), EndOfStream: true,
			},
		},
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv body: %v", err)
	}
	imm, ok := resp.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("FAIL OPEN: expected ImmediateResponse for admin grant on delete tool (Finding 5), got %T",
			resp.Response)
	}
	if imm.ImmediateResponse.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403 (hard-pin read-only for sandbox-agent), got %v",
			imm.ImmediateResponse.GetStatus().GetCode())
	}
	_ = stream.CloseSend()
}
