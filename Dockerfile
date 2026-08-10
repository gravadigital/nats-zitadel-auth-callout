FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/callout ./cmd/callout

FROM alpine:3.21

RUN adduser -D -u 1001 callout

# The mount points have to exist: the rootfs is read-only and runc cannot create them when
# bringing the container up.
RUN mkdir -p /etc/auth-callout /etc/nats-creds

COPY --from=builder /out/callout /usr/local/bin/callout

# The configuration (rules.yaml + templates) and the credentials are mounted as volumes: they
# do not live in the image. See deploy/nats/ in the Hermes repo.
USER callout
ENTRYPOINT ["/usr/local/bin/callout"]
