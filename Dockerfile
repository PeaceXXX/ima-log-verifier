# Multi-stage build: compile statically, ship a minimal runtime image.
FROM golang:1.24 AS builder
WORKDIR /src
COPY go.mod .
COPY cmd ./cmd
COPY pkg ./pkg
RUN go build -trimpath -ldflags="-s -w" -o /out/ima-verify ./cmd/ima-verify && \
    go build -trimpath -ldflags="-s -w" -o /out/ima-gen ./cmd/ima-gen

FROM gcr.io/distroless/static-debian12 AS runtime
COPY --from=builder /out/ima-verify /usr/local/bin/ima-verify
COPY --from=builder /out/ima-gen /usr/local/bin/ima-gen
ENTRYPOINT ["/usr/local/bin/ima-verify"]
