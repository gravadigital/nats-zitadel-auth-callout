FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/callout ./cmd/callout

FROM alpine:3.21

RUN adduser -D -u 1001 callout

# Los puntos de montaje tienen que existir: el rootfs es de solo lectura y runc no puede
# crearlos al levantar el contenedor.
RUN mkdir -p /etc/auth-callout /etc/nats-creds

COPY --from=builder /out/callout /usr/local/bin/callout

# La configuración (rules.yaml + templates) y las credenciales se montan por volumen:
# no viven en la imagen. Ver deploy/nats/ en el repo de Hermes.
USER callout
ENTRYPOINT ["/usr/local/bin/callout"]
