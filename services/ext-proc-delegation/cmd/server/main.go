// Command server runs the ext-proc-delegation gRPC service.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

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

	_ = x509Source // available for mTLS if needed in future

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

	// Build gRPC server.
	srv := grpc.NewServer()
	extprocSrv := extproc.NewServer(cfg, kcClient, vaultClient, verifier, jitVerifier)
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
