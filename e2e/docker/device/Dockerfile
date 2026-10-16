# syntax=docker/dockerfile:1.7
# device: the real `ak` CLI built from a pinned agentkit commit, plus the
# e2e helpers that drive it. The `agentkit` build context is a `git archive`
# of apps/cli at that commit, made by run.sh (agentkit is private, so the
# image never clones it and needs no credential).
# The CLI is cross-compiled on the build platform for the target one, so an
# amd64 image builds natively fast on arm64 hosts and vice versa.
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS build
ARG AGENTKIT_SHA=unknown
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY --from=agentkit . .
WORKDIR /src/apps/cli
# CGO off and the nobundle tag: a headless CLI without the desktop runtime
# or the embedded dashboard, the build agentkit documents for containers.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags nobundle -trimpath \
      -ldflags "-X main.Commit=${AGENTKIT_SHA}" -o /out/ak .

FROM debian:bookworm-slim
ARG AGENTKIT_SHA=unknown
LABEL org.opencontainers.image.revision.agentkit="${AGENTKIT_SHA}"
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 socat ca-certificates procps tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 1000 dev
COPY --from=build /out/ak /usr/local/bin/ak
COPY e2e/docker/device/bin/ /usr/local/bin/
USER dev
WORKDIR /home/dev
ENV HOME=/home/dev \
    AGENTKIT_HOME=/home/dev/.agentkit \
    AGENTKIT_SECRETS_BACKEND=file \
    AGENTKIT_REGISTRY_URL=http://127.0.0.1:8788 \
    E2E_VAULT_ORIGIN=http://127.0.0.1:8787 \
    E2E_PASSPHRASE_FILE=/run/e2e/passphrase \
    NO_COLOR=1
ENTRYPOINT ["/usr/local/bin/device-entrypoint.sh"]
