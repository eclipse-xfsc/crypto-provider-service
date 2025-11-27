FROM golang:1.21.5 as builder

WORKDIR /go/src/github.com/eclipse-xfsc/crypto-provider-service

ARG APP_REPO_TAG

ADD . .

RUN CGO_ENABLED=1 GOOS=linux go build -mod=vendor -o  /tmp/signer ./cmd/signer/...

FROM golang:1.21.5 as runner
RUN mkdir /opt/plugins
COPY --from=builder /tmp/signer /opt/signer
WORKDIR /opt
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && update-ca-certificates \
 && rm -rf /var/lib/apt/lists/*

CMD ["./signer"]
