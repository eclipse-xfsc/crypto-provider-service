FROM golang:1.21.5 as pluginBuilder
ARG PLUGIN_URL_LOCAL="https://gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/plugins/local-provider.git --branch v0.0.6"
WORKDIR /go/src/github.com/eclipse-xfsc/crypto-provider-service
RUN git clone $PLUGIN_URL_LOCAL .
RUN CGO_ENABLED=1 GOOS=linux go build --buildmode=plugin -mod=vendor -o /local-provider.so 


FROM golang:1.21.5 as pluginBuilder2
ARG PLUGIN_URL_PROD="https://gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/plugins/hashicorp-vault-provider.git --branch v1.2.4"
WORKDIR /go/src/github.com/eclipse-xfsc/crypto-provider-service
RUN git clone $PLUGIN_URL_PROD .
RUN CGO_ENABLED=1 GOOS=linux go build --buildmode=plugin -mod=vendor -o /hashicorp-vault-provider.so 

FROM golang:1.21.5 as builder

WORKDIR /go/src/github.com/eclipse-xfsc/crypto-provider-service

ARG APP_REPO_TAG

ADD . .

RUN CGO_ENABLED=1 GOOS=linux go build -mod=vendor -o  /tmp/signer ./cmd/signer/...

FROM golang:1.21.5 as runner
RUN mkdir /opt/plugins
COPY --from=builder /tmp/signer /opt/signer
COPY --from=pluginBuilder local-provider.so /opt/plugins/local-provider.so
COPY --from=pluginBuilder2 hashicorp-vault-provider.so /opt/plugins/hashicorp-vault-provider.so 
WORKDIR /opt

CMD ["./signer"]
