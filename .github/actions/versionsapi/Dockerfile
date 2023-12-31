FROM golang:1.21.1@sha256:c416ceeec1cdf037b80baef1ccb402c230ab83a9134b34c0902c542eb4539c82 as builder

# Download project root dependencies
WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
COPY operators/constellation-node-operator/api/go.mod ./operators/constellation-node-operator/api/go.mod
COPY operators/constellation-node-operator/api/go.sum ./operators/constellation-node-operator/api/go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

COPY . .

# Build
WORKDIR /workspace/internal/api/versionsapi/cli
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o versionsapi .

FROM scratch as release

COPY --from=builder /workspace/internal/api/versionsapi/cli/versionsapi .

CMD ["/notIntendedToBeExecuted"]
