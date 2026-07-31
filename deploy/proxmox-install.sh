#!/usr/bin/env bash
#
# certguard — Proxmox LXC installer.
#
# Run this ON THE PROXMOX HOST (as root). It creates a small Debian 12 LXC,
# installs Docker, deploys certguard, and prints the URL. No prior setup needed.
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/rudeboi1992/certguard/main/deploy/proxmox-install.sh)"
#
# Everything below has a sane default; override any of them inline, e.g.
#   CORES=4 RAM=2048 DISK=8 STORAGE=local-zfs bash -c "$(curl -fsSL ...)"
#
set -euo pipefail

# ---- settings (override via environment) -----------------------------------
CTID="${CTID:-}"                       # container id (default: next free)
HOSTNAME_="${HOSTNAME_:-certguard}"    # LXC hostname
CORES="${CORES:-2}"                    # vCPU cores
RAM="${RAM:-1024}"                     # MB
DISK="${DISK:-6}"                      # GB root disk (Docker + image need room)
BRIDGE="${BRIDGE:-vmbr0}"              # network bridge
STORAGE="${STORAGE:-}"                 # container root disk storage (auto-detected if empty)
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-}"  # template storage (auto-detected if empty)
PORT="${PORT:-8181}"                   # host port certguard listens on (plain mode)
IMAGE="${IMAGE:-ghcr.io/rudeboi1992/certguard:latest}"
# MODE=plain    → HTTP on :PORT (simplest; fine on a trusted LAN)
# MODE=internal → bundled Caddy + trusted internal cert on :443 (green padlock
#                 after you install the CA). Uses DOMAIN if set, else the LXC IP.
MODE="${MODE:-plain}"
DOMAIN="${DOMAIN:-}"
# Optional: auto-create the first admin (else you make it in the browser).
CG_ADMIN_EMAIL="${CG_ADMIN_EMAIL:-}"
CG_ADMIN_PASSWORD="${CG_ADMIN_PASSWORD:-}"

# ---- pretty output ----------------------------------------------------------
GN='\033[1;92m'; BL='\033[1;94m'; RD='\033[1;91m'; YW='\033[1;93m'; CL='\033[0m'
msg()  { echo -e " ${GN}✓${CL} $1"; }
info() { echo -e " ${BL}·${CL} $1"; }
warn() { echo -e " ${YW}!${CL} $1"; }
die()  { echo -e " ${RD}✗ $1${CL}" >&2; exit 1; }

# ---- preflight --------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "Run this as root on the Proxmox host."
command -v pct >/dev/null 2>&1 || die "This must run on a Proxmox VE host (pct not found)."

echo -e "${BL}certguard — Proxmox LXC installer${CL}"

# Next free container id, if not given.
if [ -z "$CTID" ]; then
  CTID="$(pvesh get /cluster/nextid)"
fi
info "Using container ID ${CTID}"

# Auto-detect storage — not every host has "local-lvm". Pick the first storage
# that can hold a container root disk (rootdir) / templates (vztmpl).
if [ -z "$STORAGE" ]; then
  STORAGE="$(pvesm status -content rootdir 2>/dev/null | awk 'NR>1{print $1; exit}')"
  [ -n "$STORAGE" ] || die "No storage supports container disks (rootdir). Set STORAGE=... explicitly."
fi
if [ -z "$TEMPLATE_STORAGE" ]; then
  TEMPLATE_STORAGE="$(pvesm status -content vztmpl 2>/dev/null | awk 'NR>1{print $1; exit}')"
  [ -n "$TEMPLATE_STORAGE" ] || die "No storage supports templates (vztmpl). Set TEMPLATE_STORAGE=... explicitly."
fi
info "Root disk on '${STORAGE}', templates on '${TEMPLATE_STORAGE}'"

# ---- ensure a Debian 12 template is available -------------------------------
info "Checking for a Debian 12 LXC template…"
pveam update >/dev/null 2>&1 || true
TEMPLATE="$(pveam available --section system 2>/dev/null | awk '{print $2}' \
  | grep -E '^debian-12-standard_.*\.tar\.(zst|gz|xz)$' | sort -V | tail -1)"
[ -n "$TEMPLATE" ] || die "Could not find a debian-12-standard template via pveam."
if ! pveam list "$TEMPLATE_STORAGE" 2>/dev/null | grep -q "$TEMPLATE"; then
  info "Downloading ${TEMPLATE} to ${TEMPLATE_STORAGE}…"
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE" >/dev/null
fi
TEMPLATE_REF="${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE}"
msg "Template ready: ${TEMPLATE}"

# ---- create the container ---------------------------------------------------
# Unprivileged + nesting/keyctl so Docker runs cleanly inside the LXC.
info "Creating LXC ${CTID} (${CORES} cores, ${RAM}MB RAM, ${DISK}GB disk)…"
pct create "$CTID" "$TEMPLATE_REF" \
  --hostname "$HOSTNAME_" \
  --cores "$CORES" --memory "$RAM" --swap 512 \
  --rootfs "${STORAGE}:${DISK}" \
  --net0 "name=eth0,bridge=${BRIDGE},ip=dhcp" \
  --unprivileged 1 \
  --features nesting=1,keyctl=1 \
  --onboot 1 \
  --description "certguard — expiry monitor (installed by proxmox-install.sh)" \
  >/dev/null
msg "Container created"

info "Starting container…"
pct start "$CTID"

# Wait for the network / DHCP lease.
info "Waiting for network…"
for i in $(seq 1 30); do
  if pct exec "$CTID" -- getent hosts deb.debian.org >/dev/null 2>&1; then break; fi
  sleep 2
  [ "$i" -eq 30 ] && die "Container never got network — check the bridge (${BRIDGE})."
done
msg "Network up"

# ---- install Docker inside --------------------------------------------------
info "Installing Docker inside the container (this takes a minute)…"
pct exec "$CTID" -- bash -c "
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl docker.io >/dev/null
  systemctl enable --now docker >/dev/null 2>&1 || true
"
msg "Docker installed"

# ---- deploy certguard -------------------------------------------------------
IP="$(pct exec "$CTID" -- hostname -I 2>/dev/null | awk '{print $1}')"
ENV_ADMIN=""
if [ -n "$CG_ADMIN_EMAIL" ] && [ -n "$CG_ADMIN_PASSWORD" ]; then
  ENV_ADMIN="-e CERTGUARD_ADMIN_EMAIL=${CG_ADMIN_EMAIL} -e CERTGUARD_ADMIN_PASSWORD=${CG_ADMIN_PASSWORD}"
fi

if [ "$MODE" = "internal" ]; then
  # certguard's own self-signed cert is a CA cert (ExtKeyUsage serverAuth) that
  # covers IP SANs — so, unlike a CA-signed hostname cert, it gives a trusted
  # padlock by bare IP with no DNS once you install it. One container, no proxy.
  SITE="${DOMAIN:-$IP}"
  HOSTS="$IP"; [ -n "$DOMAIN" ] && HOSTS="${IP},${DOMAIN}"
  info "Deploying certguard over HTTPS (self-signed, trusted-after-install) for ${SITE}…"
  pct exec "$CTID" -- bash -c "
    docker rm -f certguard certguard-caddy >/dev/null 2>&1 || true
    docker run -d --name certguard --restart unless-stopped \
      -p 443:8181 \
      -e CERTGUARD_TLS_AUTO=1 \
      -e CERTGUARD_TLS_HOSTS=${HOSTS} \
      -e CERTGUARD_TLS_CERT=/data/tls-cert.pem \
      -e CERTGUARD_TLS_KEY=/data/tls-key.pem \
      -e CERTGUARD_CA_FILE=/data/tls-cert.pem \
      ${ENV_ADMIN} \
      -v certguard-data:/data ${IMAGE} >/dev/null
  "
  URL="https://${SITE}"
else
  info "Pulling and starting certguard (plain HTTP)…"
  pct exec "$CTID" -- bash -c "
    docker rm -f certguard >/dev/null 2>&1 || true
    docker run -d --name certguard --restart unless-stopped \
      -p ${PORT}:8181 -v certguard-data:/data ${ENV_ADMIN} ${IMAGE} >/dev/null
  "
  URL="http://${IP}:${PORT}"
fi
msg "certguard is running"

# ---- summary ----------------------------------------------------------------
echo
echo -e "${GN}────────────────────────────────────────────────────────${CL}"
echo -e "${GN} certguard is up!${CL}"
echo -e "   URL:        ${BL}${URL}${CL}"
echo -e "   Container:  LXC ${CTID} (${HOSTNAME_})"
if [ -n "$CG_ADMIN_EMAIL" ]; then
  echo -e "   Admin:      ${CG_ADMIN_EMAIL} (created for you)"
else
  echo -e "   Next:       open the URL and create your admin account"
fi
echo -e "${GN}────────────────────────────────────────────────────────${CL}"
echo
if [ "$MODE" = "internal" ]; then
  warn "First visit warns (self-signed). To get the green padlock, per device:"
  warn "  1) open ${URL}/ca.crt (or Settings → Download CA certificate)"
  warn "  2) install it into 'Trusted Root Certification Authorities'"
  warn "  3) FULLY QUIT and reopen your browser (a refresh isn't enough)"
else
  warn "This serves plain HTTP — fine on a trusted LAN/VPN. For a trusted"
  warn "padlock, re-run with MODE=internal (bundled Caddy + local CA)."
fi
echo
info "Manage it:  pct enter ${CTID}   ·   docker logs -f certguard"
