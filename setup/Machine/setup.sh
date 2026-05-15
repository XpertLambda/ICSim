#!/bin/bash
# =============================================================================
# CH-Workshop (Barbhack ICSim Fork) Setup Script — Part 1: CAN Bus Security Lab
# Source    : https://github.com/phil-eqtech/CH-Workshop
# Target OS : Kali Linux (tested on 2024.x)
# Author    : IoV Security Lab — IMT Atlantique
# =============================================================================
# This script installs the CH-Workshop fork of ICSim, which extends the base
# simulator with:
#   - Luminosity sensor & automatic headlights (new CAN signals)
#   - UDS diagnostic protocol (sessions, Security Access, VIN via OBD-II)
#   - 6 scored challenges (100 pts total)
#
# Steps:
#   1. Installs all required dependencies
#   2. Loads the vcan kernel modules and creates a persistent vcan0 interface
#   3. Clones and compiles CH-Workshop from source
#   4. Installs helper launch scripts in /usr/local/bin
#   5. Creates a systemd service so vcan0 survives reboots
#
# Run as root:  sudo bash setup.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Please run this script as root: sudo bash $0"

INSTALL_DIR="/opt/CH-Workshop"      # repository root
BIN_DIR="/opt/CH-Workshop/CAN"     # binaries live in the CAN/ subdirectory
PID_FILE="/tmp/icsim.pids"         # stores PIDs of every process we launch

# =============================================================================
# STEP 1 — System update & dependency installation
# =============================================================================
info "Step 1/5 — Updating package lists..."
apt-get update -qq

info "Step 1/5 — Installing dependencies..."
apt-get install -y --no-install-recommends \
    git \
    build-essential \
    can-utils \
    libsdl2-dev \
    libsdl2-image-dev \
    iproute2 \
    procps \
    net-tools

info "All dependencies installed."

# =============================================================================
# STEP 2 — Load vcan kernel modules & make them persistent
# =============================================================================
info "Step 2/5 — Loading CAN kernel modules..."

modprobe can  || error "Failed to load 'can' module."
modprobe vcan || error "Failed to load 'vcan' module."

for mod in can vcan; do
    if ! grep -qx "$mod" /etc/modules 2>/dev/null; then
        echo "$mod" >> /etc/modules
        info "$mod added to /etc/modules (persists on reboot)."
    else
        info "$mod already listed in /etc/modules."
    fi
done

# =============================================================================
# STEP 3 — Create vcan0 interface & persist it via systemd
# =============================================================================
info "Step 3/5 — Creating vcan0 interface..."

if ! ip link show vcan0 &>/dev/null; then
    ip link add dev vcan0 type vcan
    info "vcan0 created."
else
    warn "vcan0 already exists — skipping creation."
fi
ip link set up vcan0
info "vcan0 is UP."

cat > /etc/systemd/system/vcan0.service << 'EOF'
[Unit]
Description=Virtual CAN interface vcan0
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/sbin/modprobe can
ExecStartPre=/sbin/modprobe vcan
ExecStart=/bin/bash -c '\
    ip link show vcan0 2>/dev/null && ip link delete vcan0 2>/dev/null || true; \
    ip link add dev vcan0 type vcan && ip link set up vcan0'
ExecStop=/bin/bash -c 'ip link delete vcan0 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vcan0.service
info "vcan0.service enabled — auto-starts on every boot."

# =============================================================================
# STEP 4 — Clone & build CH-Workshop
# =============================================================================
info "Step 4/5 — Cloning CH-Workshop repository..."

if [[ -d "$INSTALL_DIR" ]]; then
    warn "$INSTALL_DIR already exists — pulling latest changes."
    git -C "$INSTALL_DIR" pull
else
    git clone https://github.com/phil-eqtech/CH-Workshop.git "$INSTALL_DIR"
fi

# The actual source and binaries live in the CAN/ subdirectory
info "Building CH-Workshop (CAN module)..."
cd "$BIN_DIR"

# Note: make clean does NOT remove lib.o — this is intentional.
# The repo ships a prebuilt lib.o. If it fails to link (wrong arch),
# recompile manually: gcc -c lib.c -o lib.o
make clean 2>/dev/null || true
make

[[ -f "$BIN_DIR/icsim" ]]    || error "Build failed: icsim binary not found."
[[ -f "$BIN_DIR/controls" ]] || error "Build failed: controls binary not found."
info "CH-Workshop built successfully."

# =============================================================================
# STEP 5 — Install helper launcher scripts
# =============================================================================
info "Step 5/5 — Installing launcher scripts..."

# ── icsim-start ───────────────────────────────────────────────────────────────
#
# Lab default: -X flag (no background traffic).
# Background traffic ON is opt-in via --noise flag for advanced exercises.
#
# Why -X by default?
#   controls.c forks a canplayer child replaying sample-can.log in an
#   infinite loop (-l i). For introductory lab work this creates confusing
#   noise. Students can opt-in with --noise when they are ready.
#
# Why PID file instead of pkill -f "icsim"?
#   pkill -f "icsim" matches icsim-start and icsim-stop scripts too,
#   causing a SIGTERM feedback loop (icsim-start trap → icsim-stop →
#   pkill icsim-start → trap fires again → infinite loop).
#   Storing PIDs avoids all pattern-matching ambiguity.
#
cat > /usr/local/bin/icsim-start << EOF
#!/bin/bash
# Usage: icsim-start [--noise]
#   (default)  Clean bus — no background CAN traffic  (-X mode)
#   --noise    Enable background CAN traffic (realistic noise for advanced exercises)
#
# CH-Workshop note: icsim and controls share internal state via a CAN control
# frame on 0x007. If one process dies, restart BOTH — they will desync otherwise.

ICSIM_DIR="$BIN_DIR"
PID_FILE="$PID_FILE"
CONTROLS_FLAGS="-X"

if [[ "\${1:-}" == "--noise" ]]; then
    CONTROLS_FLAGS=""
    echo "[icsim-start] Background traffic ON (--noise). Bus will be noisy."
else
    echo "[icsim-start] Clean bus mode (default). Use --noise for realistic traffic."
fi

# Ensure vcan0 is up
if ! ip link show vcan0 &>/dev/null; then
    echo "[icsim-start] vcan0 not found — bringing it up..."
    modprobe can && modprobe vcan
    ip link add dev vcan0 type vcan
    ip link set up vcan0
fi

# Kill any leftover processes before starting fresh
if [[ -f "\$PID_FILE" ]]; then
    echo "[icsim-start] Cleaning up leftover processes..."
    icsim-stop
fi

cd "\$ICSIM_DIR"

echo "[icsim-start] Starting icsim..."
./icsim vcan0 &
ICSIM_PID=\$!
sleep 1

echo "[icsim-start] Starting controls..."
./controls \$CONTROLS_FLAGS vcan0 &
CTRL_PID=\$!
sleep 0.5

# Write PIDs to file — icsim-stop reads these instead of using pkill -f
echo "ICSIM_PID=\$ICSIM_PID" > "\$PID_FILE"
echo "CTRL_PID=\$CTRL_PID"   >> "\$PID_FILE"

echo ""
echo "  icsim    PID: \$ICSIM_PID"
echo "  controls PID: \$CTRL_PID"
echo "  PID file    : \$PID_FILE"
echo ""
echo "  Run 'icsim-stop' in another terminal to stop cleanly."
echo "  (Do NOT use Ctrl+C here — use icsim-stop)"
echo "  WARNING: if one window closes unexpectedly, restart BOTH with icsim-start."

# Wait without a trap — icsim-stop handles cleanup externally
wait \$ICSIM_PID \$CTRL_PID 2>/dev/null || true
rm -f "\$PID_FILE"
echo "[icsim-start] All processes finished."
EOF
chmod +x /usr/local/bin/icsim-start

# ── icsim-stop ────────────────────────────────────────────────────────────────
#
# Reads PIDs from the PID file written by icsim-start.
# Falls back to path-specific patterns only if PID file is missing.
#
# IMPORTANT: we use full paths like "/opt/CH-Workshop/CAN/icsim" in pkill -f,
# NOT bare names like "icsim". Bare names match the icsim-start and
# icsim-stop scripts themselves, causing an infinite SIGTERM loop.
#
cat > /usr/local/bin/icsim-stop << EOF
#!/bin/bash
PID_FILE="$PID_FILE"
BIN_DIR="$BIN_DIR"

echo "[icsim-stop] Stopping ICSim (CH-Workshop)..."

if [[ -f "\$PID_FILE" ]]; then
    # Primary method: kill by saved PIDs (precise, no name collision)
    source "\$PID_FILE"
    for pid_var in ICSIM_PID CTRL_PID; do
        pid="\${!pid_var:-}"
        if [[ -n "\$pid" ]] && kill -0 "\$pid" 2>/dev/null; then
            kill "\$pid" 2>/dev/null && echo "  Killed \$pid_var (PID \$pid)"
        fi
    done
    rm -f "\$PID_FILE"
else
    # Fallback: use full binary path to avoid matching script names
    echo "  (no PID file — using path-based fallback)"
    pkill -f "\$BIN_DIR/icsim"    2>/dev/null && echo "  icsim stopped."    || true
    pkill -f "\$BIN_DIR/controls" 2>/dev/null && echo "  controls stopped." || true
fi

# Always kill canplayer regardless of method:
# controls.c forks canplayer as a child. If controls was force-killed
# (SIGKILL), the atexit(kill_child) handler never runs and canplayer
# becomes an orphan flooding vcan0 indefinitely.
pkill -x canplayer 2>/dev/null && echo "  canplayer stopped." || true

echo "[icsim-stop] Done."
EOF
chmod +x /usr/local/bin/icsim-stop

# ── icsim-replay ──────────────────────────────────────────────────────────────
cat > /usr/local/bin/icsim-replay << 'EOF'
#!/bin/bash
# Usage: icsim-replay <logfile.log>
LOGFILE="${1:-}"
[[ -z "$LOGFILE" ]] && { echo "Usage: icsim-replay <logfile.log>"; exit 1; }
[[ -f "$LOGFILE" ]]  || { echo "File not found: $LOGFILE"; exit 1; }
echo "[icsim-replay] Replaying $LOGFILE on vcan0..."
canplayer -I "$LOGFILE" vcan0=vcan0
EOF
chmod +x /usr/local/bin/icsim-replay

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo -e "${GREEN}======================================================${NC}"
echo -e "${GREEN}  CH-Workshop (Barbhack ICSim fork) installed!${NC}"
echo -e "${GREEN}======================================================${NC}"
echo ""
echo "  Install directory : $INSTALL_DIR"
echo "  Binaries          : $BIN_DIR"
echo "  vcan0 status      : $(ip link show vcan0 | head -1)"
echo ""
echo "  Commands:"
echo "    icsim-start          — start with clean bus (no background noise)"
echo "    icsim-start --noise  — start with background CAN traffic (advanced)"
echo "    icsim-stop           — stop icsim + controls + canplayer cleanly"
echo "    icsim-replay <file>  — replay a candump log onto vcan0"
echo ""
echo "  New vs standard ICSim:"
echo "    - Luminosity sensor (0x39C) + headlights (0x340)"
echo "    - UDS diagnostics on 0x7E0 (sessions, Security Access, VIN)"
echo "    - 6 scored challenges (100 pts total)"
echo "    - WARNING: always restart BOTH icsim and controls together"
echo ""
echo -e "${YELLOW}  Reboot recommended to verify persistence of vcan0.${NC}"
echo ""