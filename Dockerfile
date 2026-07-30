# syntax=docker/dockerfile:1

# --- build stage -----------------------------------------------------------
FROM golang:1.25-alpine AS build
WORKDIR /src

# Cache module downloads separately from source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=docker
# CGO is off (modernc.org/sqlite is pure Go) so the binary is fully static.
RUN CGO_ENABLED=0 GOOS=linux go build \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/certguard . \
    && mkdir /data

# --- runtime stage ---------------------------------------------------------
# distroless/static is ~2MB, ships CA certificates (needed to verify the certs
# we scan) and tzdata, and runs as a non-root user by default.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/certguard /certguard
COPY --from=build --chown=65532:65532 /data /data

EXPOSE 8181
# Keep the database AND the secret-vault master key in the persisted volume, so
# stored secrets stay decryptable when the container is recreated.
ENV CERTGUARD_DB_DSN=/data/certguard.db \
    CERTGUARD_KEY_FILE=/data/certguard.key
VOLUME ["/data"]

ENTRYPOINT ["/certguard"]
CMD ["serve"]
