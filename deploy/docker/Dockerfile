# syntax=docker/dockerfile:1

FROM golang:1.25.13 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/envelope ./cmd/envelope

# Goose resolves its app root by walking up from the binary's directory
# looking for go.mod (see goose/utils/path.AppRoot), then derives the
# config directory from that root. A distroless runtime has no go.mod, so
# ship a stand-in marker file alongside the binary purely so that lookup
# resolves to /app instead of failing.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /src/go.mod ./go.mod
COPY --from=builder /out/envelope ./envelope
COPY config/config.example.yaml ./config/config.yaml

# gcr.io/distroless/*:nonroot already runs as the numeric UID 65532 by
# default — re-declaring USER nonroot:nonroot here would overwrite that
# with the non-numeric name form, which Kubernetes's runAsNonRoot check
# can't statically verify without running the container (confirmed
# against a real cluster: every pod failed to start with "image has
# non-numeric user (nonroot)" until this line was removed).
EXPOSE 8080
ENTRYPOINT ["/app/envelope"]
