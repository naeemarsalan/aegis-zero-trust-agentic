package extproc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/config"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/extproc"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/jwks"
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
	data map[string]interface{}
	err  error
}

func (s *stubVault) FetchToolSecret(_ context.Context, _ string) (map[string]interface{}, error) {
	return s.data, s.err
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
