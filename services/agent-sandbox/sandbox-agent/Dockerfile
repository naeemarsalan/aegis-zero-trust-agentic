FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /sandbox-agent .
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /sandbox-agent /sandbox-agent
USER 65532:65532
ENTRYPOINT ["/sandbox-agent"]
