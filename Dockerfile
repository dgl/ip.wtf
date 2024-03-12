# Standard Debian Dockerfile, requires BuildKit:
#   DOCKER_BUILDKIT=1 docker build .
# Master copy lives in https://github.com/dgl/go-base

# This can be used in projects that follow standard Go layout, all binaries
# will be installed in /app, then the only modification required should be the
# binary and flags in the final RUN and CMD (and potentially the ones mentioned
# for CGO). If you don't need CGO then 'ko' (https://ko.build) might be a
# better choice.

# Set --build-arg BUILD_DEBUG=1 to get a distroless debug image.
ARG BUILD_DEBUG

# These must match so distroless version == golang image version.
ARG BUILD_DISTRO_CODENAME=bookworm
ARG BUILD_DISTRO_VERSION=12

# -----
# Cache go.mod downloads
FROM golang:1-${BUILD_DISTRO_CODENAME} AS base-cache
WORKDIR /git
RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=bind,source=go.mod,target=go.mod \
    go mod download -x

FROM base-cache AS build
# Use bash, no need to subject ourselves to sh-isms in RUN in the 21st century.
SHELL ["/bin/bash", "-c"]
WORKDIR /git

# -----
# Run tests with the versions we'll build; build the binary.
# Using --mount makes this faster as it avoids copying.
RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=cache,target=/root/.cache/go-build/ \
    --mount=type=bind,target=. \
    set -x && \
    # Remove this and swap "static-debian" to "base-nossl-debian" below to use
    # libraries needing CGO.
    export CGO_ENABLED=0 && \
    go test -v /git/... && \
    V="$(git describe --always --tags --dirty)" && \
    # For non-dirty builds only: check out the module so build info is correct.
    if [[ $(git status --porcelain) = "" ]] && [[ ${V/dirty} = $V ]]; then \
      MOD="$(go list -m)" && \
      git config --global url."/git".insteadOf "https://$MOD" && \
      # Verify the cache here for sanity.
      go mod verify && \
      # Git describe output looks like "${tag}-g${commit_id}" if it isn't fully
      # described by a tag. So use the raw commit ID for compatibility with Go
      # version strings.
      if [[ ${V/-g*} != $V ]]; then \
        V="$(git rev-parse HEAD)"; \
      fi && \
      GOPRIVATE="$MOD" GOBIN=/app go install $MOD/...@$V; \
    else \
      GOBIN=/app go install /git/...; \
    fi && \
    # Put the binary checksums into the build log, not required, but useful
    # info in the log.
    sha256sum /app/*

# -----
# Use nonroot distroless image (runs as uid 65532).
FROM gcr.io/distroless/static-debian${BUILD_DISTRO_VERSION}:${BUILD_DEBUG:+debug-}nonroot
WORKDIR /data
COPY --from=build /app /app

# Ensure ENTRYPOINT is set to empty, so a debug image runs normally.
ENTRYPOINT []
# Run the binary using the final image, to catch a CGO binary using static
# base, etc. (This costs an extra layer, but worth it.)
RUN ["/app/ip.wtf", "-version"]

CMD ["/app/ip.wtf", "-listen=:8080"]
# For development tools.
EXPOSE 8080
