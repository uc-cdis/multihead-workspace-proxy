FROM quay.io/cdis/golang:1.23-bookworm AS base

ARG TARGETOS
ARG TARGETARCH

ENV appname=multihead-workspace-proxy

ENV CGO_ENABLED=0
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}
ENV GOTOOLCHAIN=go1.26.5

FROM base AS builder
WORKDIR $GOPATH/src/github.com/uc-cdis/multihead-workspace-proxy/

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN GITCOMMIT=$(git rev-parse HEAD) \
    GITVERSION=$(git describe --always --tags) \
    && go build \
    -ldflags="-X 'github.com/uc-cdis/multihead-workspace-proxy/version.GitCommit=${GITCOMMIT}' -X 'github.com/uc-cdis/multihead-workspace-proxy/version.GitVersion=${GITVERSION}'" \
    -o /multihead-workspace-proxy

RUN echo "nobody:x:65534:65534:Nobody:/:" > /etc_passwd

# FROM scratch

FROM amazonlinux:2023

COPY --from=builder /etc_passwd /etc/passwd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /multihead-workspace-proxy /multihead-workspace-proxy
# USER nobody
ENTRYPOINT ["/multihead-workspace-proxy"]
CMD ["/multihead-workspace-proxy"]
