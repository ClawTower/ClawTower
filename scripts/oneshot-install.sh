#!/usr/bin/env bash
# ClawAV Oneshot Installer — Downloads pre-built binaries from GitHub Releases
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/coltz108/ClawAV/main/scripts/oneshot-install.sh | sudo bash
#   curl -sSL https://raw.githubusercontent.com/coltz108/ClawAV/main/scripts/oneshot-install.sh | sudo bash -s -- --version v0.1.0
#
set -euo pipefail

REPO="coltz108/ClawAV"
VERSION="${1:-latest}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[CLAWAV]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Must run as root (pipe to sudo bash, or run with sudo)"

# ── Detect architecture ──────────────────────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)   ARCH_LABEL="x86_64" ;;
    aarch64|arm64)   ARCH_LABEL="aarch64" ;;
    *)               die "Unsupported architecture: $ARCH (need x86_64 or aarch64)" ;;
esac
log "Detected architecture: $ARCH_LABEL"

# ── Resolve version ──────────────────────────────────────────────────────────
if [[ "$VERSION" == "latest" ]]; then
    log "Fetching latest release..."
    VERSION=$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    [[ -n "$VERSION" ]] || die "Could not determine latest version. Check https://github.com/$REPO/releases"
fi
log "Installing ClawAV $VERSION"

# ── Download binaries ────────────────────────────────────────────────────────
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
CLAWAV_ARTIFACT="clawav-${ARCH_LABEL}-linux"
CLAWSUDO_ARTIFACT="clawsudo-${ARCH_LABEL}-linux"

log "Downloading $CLAWAV_ARTIFACT..."
curl -sSL -f -o "$TMPDIR/clawav" "$BASE_URL/$CLAWAV_ARTIFACT" || die "Failed to download clawav binary. Check version exists: $BASE_URL/$CLAWAV_ARTIFACT"

log "Downloading $CLAWSUDO_ARTIFACT..."
curl -sSL -f -o "$TMPDIR/clawsudo" "$BASE_URL/$CLAWSUDO_ARTIFACT" || die "Failed to download clawsudo binary. Check version exists: $BASE_URL/$CLAWSUDO_ARTIFACT"

chmod +x "$TMPDIR/clawav" "$TMPDIR/clawsudo"

# ── Download config + policies ───────────────────────────────────────────────
log "Downloading config files..."
curl -sSL -f -o "$TMPDIR/config.toml" "https://raw.githubusercontent.com/$REPO/$VERSION/config.toml" || warn "Could not download config.toml (will use defaults)"
mkdir -p "$TMPDIR/policies"
curl -sSL -f -o "$TMPDIR/policies/default.yaml" "https://raw.githubusercontent.com/$REPO/$VERSION/policies/default.yaml" 2>/dev/null || true
curl -sSL -f -o "$TMPDIR/policies/clawsudo.yaml" "https://raw.githubusercontent.com/$REPO/$VERSION/policies/clawsudo.yaml" 2>/dev/null || true

# ── Install auditd ───────────────────────────────────────────────────────────
if ! command -v auditctl &>/dev/null; then
    log "Installing auditd..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq auditd
    elif command -v dnf &>/dev/null; then
        dnf install -y -q audit
    elif command -v pacman &>/dev/null; then
        pacman -S --noconfirm audit
    else
        warn "Could not install auditd — install it manually"
    fi
fi

# ── Create directories ───────────────────────────────────────────────────────
log "Setting up directories..."
mkdir -p /etc/clawav/policies /var/log/clawav /var/run/clawav

# ── Stop existing service ────────────────────────────────────────────────────
if systemctl is-active --quiet clawav 2>/dev/null; then
    log "Stopping existing ClawAV service..."
    systemctl stop clawav
    sleep 1
fi

# ── Install binaries ─────────────────────────────────────────────────────────
log "Installing binaries to /usr/local/bin/..."

# Remove immutable flag if upgrading
chattr -i /usr/local/bin/clawav 2>/dev/null || true
chattr -i /usr/local/bin/clawsudo 2>/dev/null || true

cp "$TMPDIR/clawav" /usr/local/bin/clawav
cp "$TMPDIR/clawsudo" /usr/local/bin/clawsudo
chmod 755 /usr/local/bin/clawav /usr/local/bin/clawsudo

# ── Install config ───────────────────────────────────────────────────────────
if [[ ! -f /etc/clawav/config.toml ]]; then
    [[ -f "$TMPDIR/config.toml" ]] && cp "$TMPDIR/config.toml" /etc/clawav/config.toml
    log "Installed default config to /etc/clawav/config.toml — edit before starting"
else
    log "Existing config preserved at /etc/clawav/config.toml"
fi

# Install policies (don't overwrite existing)
for f in "$TMPDIR"/policies/*.yaml; do
    fname=$(basename "$f")
    [[ -f "/etc/clawav/policies/$fname" ]] || cp "$f" "/etc/clawav/policies/$fname"
done

# ── Create systemd service ───────────────────────────────────────────────────
log "Installing systemd service..."
cat > /etc/systemd/system/clawav.service <<'EOF'
[Unit]
Description=ClawAV Security Watchdog
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/clawav --headless --config /etc/clawav/config.toml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Hardening
ProtectSystem=strict
ReadWritePaths=/var/log/clawav /var/run/clawav /etc/clawav
ProtectHome=read-only
NoNewPrivileges=false
CapabilityBoundingSet=CAP_AUDIT_READ CAP_NET_ADMIN CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  🛡️  ClawAV $VERSION installed successfully!                ${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  Next steps:                                                 ║${NC}"
echo -e "${GREEN}║  1. Edit config:    nano /etc/clawav/config.toml             ║${NC}"
echo -e "${GREEN}║  2. Set watched_user and slack_webhook_url                   ║${NC}"
echo -e "${GREEN}║  3. Start:          systemctl start clawav                   ║${NC}"
echo -e "${GREEN}║  4. Harden:         clawav harden  (locks down, optional)    ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  Binaries: /usr/local/bin/clawav, /usr/local/bin/clawsudo    ║${NC}"
echo -e "${GREEN}║  Config:   /etc/clawav/config.toml                           ║${NC}"
echo -e "${GREEN}║  Logs:     journalctl -u clawav -f                           ║${NC}"
echo -e "${GREEN}║  Uninstall: clawav uninstall                                 ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
