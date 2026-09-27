# mglab image for the Validation Lab's isolated network (deploy/compose, profile "lab").
# Build context: lab/ (the Go module builds on its own, without go.work).

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOWORK=off go build -trimpath -ldflags="-s -w" -o /out/mglab ./cmd/mglab

# Static, shell-less, non-root runtime. It includes CA certificates for
# https owner_targets.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mglab /mglab
ENTRYPOINT ["/mglab"]
