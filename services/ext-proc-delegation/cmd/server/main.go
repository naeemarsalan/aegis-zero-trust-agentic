// Command server runs the ext-proc-delegation gRPC service.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/config"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/extproc"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/jwks"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/keycloak"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/spire"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/vault"
)

const spiffeSocket = "unix:///spiffe-workload-api/spire-agent.sock"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// SPIFFE workload API socket (injected by SPIFFE CSI driver).
	socketPath := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if socketPath == "" {
		socketPath = spiffeSocket
	}

	slog.Info("initializing SPIFFE workload API", "socket", socketPath)

	x509Source, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return fmt.Errorf("SPIFFE X509Source: %w", err)
	}
	defer x509Source.Close()

	jwtSource, err := workloadapi.NewJWTSource(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return fmt.Errorf("SPIFFE JWTSource: %w", err)
	}
	defer jwtSource.Close()

	// Build the inbound JWT verifier (independent verification — the gateway
	// is NOT trusted as the identity source).
	verifier, err := jwks.New(jwks.Config{
		JWKSURL:          cfg.KeycloakJWKSURL,
		Issuer:           cfg.KeycloakIssuer,
		ExpectedAudience: cfg.ExpectedAudience,
	})
	if err != nil {
		return fmt.Errorf("jwks verifier: %w", err)
	}

	// jit-approver session-JWT verifier (gates dangerous tools, UC2). Optional:
	// if it can't be built the JIT gate is disabled (dangerous tools require
	// admin only). Verification is lazy, so a down jit-approver at startup is OK.
	var jitVerifier *jwks.Verifier
	if cfg.JITJWKSURL != "" {
		if jv, jerr := jwks.New(jwks.Config{
			JWKSURL:          cfg.JITJWKSURL,
			Issuer:           cfg.JITIssuer,
			ExpectedAudience: cfg.JITAudience,
		}); jerr != nil {
			slog.Warn("jit verifier disabled", "err", jerr)
		} else {
			jitVerifier = jv
		}
	}

	// Build downstream clients.
	kcClient := keycloak.NewClient(cfg)
	vaultClient := vault.NewClient(cfg, jwtSource)

	// Build SPIRE SVID verifier when configured. When SPIRE_JWKS_URL is set,
	// ext-proc recognises SPIRE JWT-SVIDs from the agent-sandbox workload and
	// routes them through the grant-read + RFC 8693 on-behalf path.
	var spireVerifier *spire.Verifier
	if cfg.SpireJWKSURL != "" {
		// Build the TLS config for the SPIRE OIDC JWKS HTTP client.
		// Three cases, evaluated in order:
		//   1. SPIRE_TLS_INSECURE=true  — explicit opt-in escape hatch only.
		//   2. SPIRE_CA_FILE non-empty  — pin a PEM CA bundle from disk.
		//   3. Default (secure)         — verify against system root CAs
		//      (RootCAs: nil). Correct for the LE-fronted reencrypt Route
		//      (*.apps.ocp-dev.na-launch.com). x509Source passed for API
		//      compatibility; not used for TLS anchor in the default path.
		spireHTTP, tlsErr := buildSpireHTTPClient(cfg, x509Source)
		if tlsErr != nil {
			return fmt.Errorf("SPIRE JWKS HTTP client: %w", tlsErr)
		}
		sv, svErr := spire.New(jwks.Config{
			JWKSURL:          cfg.SpireJWKSURL,
			Issuer:           cfg.SpireIssuer,
			ExpectedAudience: cfg.SpireAudience,
			HTTPClient:       spireHTTP,
		})
		if svErr != nil {
			slog.Warn("SPIRE verifier init failed — sandbox agent path disabled", "err", svErr)
		} else {
			spireVerifier = sv
			slog.Info("SPIRE verifier enabled", "jwks_url", cfg.SpireJWKSURL, "issuer", cfg.SpireIssuer)
		}
	}

	// Build gRPC server.
	srv := grpc.NewServer()
	var extprocSrv *extproc.Server
	if spireVerifier != nil {
		extprocSrv = extproc.NewServerWithSpire(cfg, kcClient, vaultClient, verifier, jitVerifier, spireVerifier)
	} else {
		extprocSrv = extproc.NewServer(cfg, kcClient, vaultClient, verifier, jitVerifier)
	}
	extprocv3.RegisterExternalProcessorServer(srv, extprocSrv)

	healthSrv := health.NewServer()
	healthpb.RegisterHealthServer(srv, healthSrv)
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	reflection.Register(srv)

	// Start Prometheus metrics server.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsSrv := &http.Server{
		Addr:    cfg.MetricsAddr,
		Handler: metricsMux,
	}
	go func() {
		slog.Info("metrics server starting", "addr", cfg.MetricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics server error", "err", err)
		}
	}()

	// Start gRPC server.
	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.GRPCAddr, err)
	}
	slog.Info("gRPC server starting", "addr", cfg.GRPCAddr)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(lis)
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
		srv.GracefulStop()
		_ = metricsSrv.Shutdown(context.Background())
		return nil
	case err := <-errCh:
		return fmt.Errorf("gRPC serve: %w", err)
	}
}

// buildSpireHTTPClient constructs the HTTP client used to fetch the SPIRE OIDC
// JWKS endpoint.
//
// Priority (evaluated in order):
//  1. SPIRE_TLS_INSECURE=true  — InsecureSkipVerify; explicit operator opt-in
//     escape hatch only. Never set in production.
//  2. SPIRE_CA_FILE non-empty  — PEM CA file pinned as the sole trust anchor.
//     Use this when the JWKS endpoint is fronted by a private/internal CA that
//     is not in the system root store (e.g. a passthrough Route with a
//     SPIRE-issued leaf cert, or an internal corporate CA).
//  3. Default (secure)         — RootCAs left nil, which instructs Go's TLS
//     stack to verify against the system root CA bundle (Mozilla/distroless
//     static image ships the Mozilla bundle). This is correct for this
//     deployment where the spire-oidc JWKS endpoint is fronted by an OpenShift
//     reencrypt Route serving a Let's Encrypt wildcard cert
//     (*.apps.ocp-dev.na-launch.com). LE is trusted by the system bundle;
//     full chain + hostname verification is performed. The SPIFFE X.509 bundle
//     is NOT used here — it would never validate an LE-issued cert and would
//     cause TLS failures that disable the SPIRE verifier (fail-closed).
func buildSpireHTTPClient(cfg *config.Config, src *workloadapi.X509Source) (*http.Client, error) {
	var tlsCfg *tls.Config

	switch {
	case cfg.SpireTLSInsecure:
		//nolint:gosec // explicit operator opt-in via SPIRE_TLS_INSECURE=true; not a default
		tlsCfg = &tls.Config{InsecureSkipVerify: true}
		slog.Warn("SPIRE JWKS TLS verification disabled — SPIRE_TLS_INSECURE=true is set; use only in non-production environments")

	case cfg.SpireCAFile != "":
		pemBytes, err := os.ReadFile(cfg.SpireCAFile)
		if err != nil {
			return nil, fmt.Errorf("read SPIRE_CA_FILE %q: %w", cfg.SpireCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("SPIRE_CA_FILE %q: no valid PEM certificates found", cfg.SpireCAFile)
		}
		tlsCfg = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		slog.Info("SPIRE JWKS TLS anchored to CA file", "path", cfg.SpireCAFile)

	default:
		// Verify against the system root CA bundle (RootCAs: nil = Go default).
		// The spire-oidc JWKS endpoint is fronted by an OpenShift reencrypt Route
		// serving a Let's Encrypt wildcard cert; system roots (distroless static
		// image ships the Mozilla bundle) trust LE. Full chain and hostname
		// verification are performed; InsecureSkipVerify remains false.
		// The x509Source SPIFFE bundle is intentionally not used here — it
		// validates SPIRE-issued certs only and would reject the LE leaf cert.
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
		slog.Info("SPIRE JWKS TLS anchored to system root CAs (trusts LE reencrypt route)")
	}

	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}
