# syntax=docker/dockerfile:1.7
# fake-akweb: the ak-web stand-in. Build context is the repository root so
# the service compiles against this checkout's akv1 module (go/).
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go/ go/
COPY e2e/docker/fake-akweb/ e2e/docker/fake-akweb/
WORKDIR /src/e2e/docker/fake-akweb
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/fake-akweb . && mkdir -p /out/shared

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/fake-akweb /usr/local/bin/fake-akweb
# The volume shared with the vault service starts out owned by the uid both
# services run as.
COPY --from=build --chown=1000:1000 /out/shared /shared
USER 1000:1000
EXPOSE 8788
ENTRYPOINT ["/usr/local/bin/fake-akweb"]
