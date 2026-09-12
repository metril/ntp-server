FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags=-s -o /exporter ./cmd/exporter

# distroless/static:nonroot can't be used: the capture socket needs
# NET_RAW, which the container's user must hold, so this keeps running as
# root like the previous Python image did.
FROM gcr.io/distroless/static

COPY --from=build /exporter /exporter

ENTRYPOINT ["/exporter"]
