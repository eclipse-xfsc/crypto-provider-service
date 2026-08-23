# ----------------------------------------
# Builder: Go 1.25
# ----------------------------------------
    FROM 1.25.14-bookworm AS builder

    WORKDIR /app
    ARG APP_REPO_TAG
    
    # Install updated CA certificates in builder
    RUN apt-get update \
        && apt-get install -y --no-install-recommends ca-certificates \
        && update-ca-certificates \
        && rm -rf /var/lib/apt/lists/*
    
    # Put updated system certs somewhere we can copy later
    RUN mkdir -p /out/certs && cp -r /etc/ssl/certs/* /out/certs/
    
    # Prepare Go build environment
    COPY go.mod go.sum ./
    COPY vendor ./vendor
    RUN go mod vendor
    
    COPY . .
    
    # Build binary
    RUN CGO_ENABLED=1 GOOS=linux \
        go build -mod=vendor -trimpath \
        -ldflags="-s -w" \
        -o /out/signer ./cmd/signer
    
    # Create plugin directory
    RUN mkdir -p /out/plugins
    
    # ----------------------------------------
    # Runner: Distroless (nonroot)
    # ----------------------------------------
    FROM gcr.io/distroless/base-debian12:nonroot AS runner
    
    WORKDIR /opt
    USER nonroot
    
    # Copy signer binary
    COPY --from=builder /out/signer /opt/signer
    
    # Copy plugins dir
    COPY --from=builder /out/plugins /opt/plugins
    
    # Copy UPDATED CA certificates into distroless
    COPY --from=builder /out/certs /etc/ssl/certs
    
    CMD ["/opt/signer"]
    