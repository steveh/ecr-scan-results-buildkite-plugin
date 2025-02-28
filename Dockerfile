FROM golang:1.21-bookworm

ARG TARGETARCH=amd64
ARG GOLANGCI_LINT_VERSION=1.52.2
ARG GORELEASER_VERSION=1.16.2

RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh |\
      sh -s -- -b $(go env GOPATH)/bin v${GOLANGCI_LINT_VERSION}

RUN curl -sSL -o goreleaser.deb https://github.com/goreleaser/goreleaser/releases/download/v${GORELEASER_VERSION}/goreleaser_${GORELEASER_VERSION}_${TARGETARCH}.deb && \
      dpkg -i goreleaser.deb && \
      rm goreleaser.deb