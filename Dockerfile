# syntax=docker/dockerfile:1

# --- build stage -----------------------------------------------------------
# Runs on the build host's native arch and cross-compiles to the target arch,
# so multi-arch images (amd64 + arm64) build fast without emulation.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
WORKDIR /src

# Cache module downloads separately from source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# The build context has no .git, so the toolchain cannot stamp the commit on its
# own — CI passes it in. Defaults keep a bare `docker build` working.
ARG VERSION=docker
ARG COMMIT=
ARG BUILD_DATE=
ARG TARGETOS TARGETARCH
# CGO is off (modernc.org/sqlite is pure Go) so the binary is fully static.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
        -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
        -o /out/certguard . \
    && mkdir /data

# --- runtime stage ---------------------------------------------------------
# distroless/static is ~2MB, ships CA certificates (needed to verify the certs
# we scan) and tzdata, and runs as a non-root user by default.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/certguard /certguard
COPY --from=build --chown=65532:65532 /data /data

EXPOSE 8181 80 443
# Keep the database, the secret-vault master key, AND any ACME certificates in
# the persisted volume so they survive a container recreate.
ENV CERTGUARD_DB_DSN=/data/certguard.db \
    CERTGUARD_KEY_FILE=/data/certguard.key \
    CERTGUARD_ACME_CACHE=/data/acme
VOLUME ["/data"]

ENTRYPOINT ["/certguard"]
CMD ["serve"]
