FROM golang:1.26-alpine AS builder

# Build metadata, supplied by the release workflow. They default to empty, in which case the
# binary falls back to the version the Go toolchain records — so a local `docker build` still
# produces something that can answer `auth-callout version`.
ARG VERSION=""
ARG COMMIT=""
ARG BUILD_DATE=""

WORKDIR /src
# go.mod and go.sum first, on their own layer: dependencies only re-download when they change,
# not on every source edit.
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# -w -s drops DWARF and the symbol table. The binary is smaller and there is no debugger
# attaching to a production container anyway.
RUN CGO_ENABLED=0 go build \
      -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
      -o /out/callout ./cmd/callout

FROM alpine:3.21

ARG VERSION=""
ARG COMMIT=""
ARG BUILD_DATE=""

# Standard OCI labels, so `docker inspect` answers what this image is without running it.
LABEL org.opencontainers.image.title="nats-zitadel-auth-callout" \
      org.opencontainers.image.description="NATS auth callout: authenticates connections against an OIDC provider and mints per-role permissions" \
      org.opencontainers.image.source="https://github.com/gravadigital/nats-zitadel-auth-callout" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# A non-root user, and a fixed uid so a mounted secret's ownership can be set without running
# the image first.
RUN adduser -D -u 1001 callout

# The mount points have to exist: the rootfs is read-only and runc cannot create them when
# bringing the container up.
RUN mkdir -p /etc/auth-callout /etc/nats-creds

COPY --from=builder /out/callout /usr/local/bin/callout

# The configuration (rules.yaml + its templates) and the credentials are mounted as volumes:
# they do not live in the image, so the same image serves every deployment and no secret is
# ever baked into a layer.
#
#   /etc/auth-callout   rules.yaml + templates/   -> point CALLOUT_RULES_PATH at it
#   /etc/nats-creds     handler credentials, signing key seeds, XKey seed
#
# Everything else is environment variables; see the configuration section of the README.
USER callout
ENTRYPOINT ["/usr/local/bin/callout"]
