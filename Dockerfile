# Multi-stage build del agente hd360-scanner.
# Incluye nmap en el runtime image (necesario para el package nmapscan).

FROM golang:1.22-alpine AS builder
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/hd360-scanner ./cmd/hd360-scanner

# Runtime mínimo + nmap binary (para nmapscan package).
# Agente necesita capacidades de raw socket para ICMP privileged → en
# compose/k8s usar `cap_add: [NET_RAW]`.
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata nmap nmap-scripts
WORKDIR /app
COPY --from=builder /out/hd360-scanner /usr/local/bin/hd360-scanner

ENTRYPOINT ["/usr/local/bin/hd360-scanner"]
CMD ["run", "--config", "/etc/hd360-scanner/agent.yaml"]
