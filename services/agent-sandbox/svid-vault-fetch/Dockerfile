FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /svid-vault-fetch .

# Distroless static — no shell, no package manager, minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /svid-vault-fetch /svid-vault-fetch
USER 65532:65532
ENTRYPOINT ["/svid-vault-fetch"]
