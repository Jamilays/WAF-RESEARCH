# syntax=docker/dockerfile:1.7
# Multi-stage build: Go 1.23 compile → small Alpine runtime with curl for
# healthchecks. CGO disabled so the binary is static.
FROM golang:1.25-alpine AS builder
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod ./
RUN go mod download
COPY main.go ./
# Vendored go.sum will be materialized by `go mod tidy` on first build; we
# force mod=mod here so the module graph is resolved deterministically.
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/coraza-proxy .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget && \
    addgroup -S waf && adduser -S -G waf waf
COPY --from=builder /out/coraza-proxy /usr/local/bin/coraza-proxy
USER waf
EXPOSE 80
ENV LISTEN_ADDR=":80" BACKEND="http://whoami:80"
ENTRYPOINT ["/usr/local/bin/coraza-proxy"]
