# syntax=docker/dockerfile:1
# Multi-stage build: Go builder -> distroless static (nonroot)
FROM golang:1.22 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /out/ext-proc-delegation \
    ./cmd/server

# --- final image ---
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /out/ext-proc-delegation /ext-proc-delegation

USER nonroot:nonroot

EXPOSE 9000 9090

ENTRYPOINT ["/ext-proc-delegation"]
