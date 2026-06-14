FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /sandbox-agent .
# ubi-minimal (NOT distroless): OpenShell's gateway wraps the sandbox container's
# command via the supervisor sideload, which invokes `sh` — a distroless image has
# no shell, so the pod fails with "CreateContainer failed: the file sh was not
# found". ubi-minimal ships /bin/sh and runs as an arbitrary (SCC-assigned) UID.
# Full ubi9/ubi (NOT distroless, NOT ubi-minimal): OpenShell's supervisor runs the
# sandbox via shell scripts (workspace-init does `sh -c '... tar ...'`) and requires
# a 'sandbox' user+group (baseline policy process.run_as_user/group=sandbox).
# distroless breaks ("sh not found"); ubi-minimal lacks tar/gzip (exit 127) and the
# build host has no RHEL repo access to microdnf-install them. The full UBI base
# already ships sh, tar, gzip, findutils, and shadow-utils (useradd).
FROM registry.access.redhat.com/ubi9/ubi:latest
RUN groupadd -g 1000 sandbox \
 && useradd -u 1000 -g 1000 -m -d /sandbox -s /bin/sh sandbox
COPY --from=build /sandbox-agent /sandbox-agent
ENTRYPOINT ["/sandbox-agent"]
