#!/usr/bin/env bash
set -euo pipefail

# Re-exec with sudo if not root (some scripts need elevated perms)
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  exec sudo -E bash "$0" "$@"
fi

# Create a timestamped reports directory and a convenient symlink
ROOT_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
REPORTS_BASE="$ROOT_DIR/reports"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
REPORTS_DIR="$REPORTS_BASE/$RUN_ID"
mkdir -p "$REPORTS_DIR"
ln -sfn "$REPORTS_DIR" "$REPORTS_BASE/latest"

# Export so child scripts can drop their files here
export REPORTS_DIR

# Predefined execution order (add more scripts here later)
SCRIPTS=(
  "home-sec-check.sh"
)

log() { echo -e "[run-all][$(date +%H:%M:%S)] $*"; }

log "Reports will be saved to: $REPORTS_DIR"

cd "$ROOT_DIR/scripts"

FAILED=0
for s in "${SCRIPTS[@]}"; do
  if [ ! -x "$s" ]; then
    if [ -f "$s" ]; then chmod +x "$s"; else log "Skipping missing $s"; continue; fi
  fi
  log "Running $s ..."
  # each script should write inside $REPORTS_DIR itself; still tee to a top-level run log
  set +e
  "./$s" 2>&1 | tee -a "$REPORTS_DIR/run-all.log"
  rc=${PIPESTATUS[0]}
  set -e
  if [ $rc -ne 0 ]; then
    log "❌ $s exited with code $rc"
    FAILED=1
  else
    log "✅ $s finished"
  fi
  echo >> "$REPORTS_DIR/run-all.log"
  echo "---" >> "$REPORTS_DIR/run-all.log"
  echo >> "$REPORTS_DIR/run-all.log"

done

log "All done. Aggregate log: $REPORTS_DIR/run-all.log"
exit $FAILED


# ===== scripts/home-sec-check.sh (v2) =====
#!/usr/bin/env bash
set -euo pipefail

# --- Output directories ---
ROOT_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
REPORTS_DIR="${REPORTS_DIR:-$ROOT_DIR/reports/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$REPORTS_DIR"
SUMMARY_OUT="$REPORTS_DIR/summary.txt"

# --- Colors (best-effort) ---
BOLD="$(tput bold 2>/dev/null || true)"; RESET="$(tput sgr0 2>/dev/null || true)"

have() { command -v "$1" >/dev/null 2>&1; }

pm_install() {
  local pkgs=("$@")
  if have apt-get; then
    # Use only main sources.list to avoid broken 3rd-party repos
    sudo apt-get -o Dir::Etc::sourcelist=/etc/apt/sources.list \
                 -o Dir::Etc::sourceparts=/dev/null \
                 update -y || true
    sudo apt-get -o Dir::Etc::sourcelist=/etc/apt/sources.list \
                 -o Dir::Etc::sourceparts=/dev/null \
                 install -y "${pkgs[@]}"
  elif have dnf; then
    sudo dnf install -y "${pkgs[@]}"
  elif have yum; then
    sudo yum install -y "${pkgs[@]}"
  elif have pacman; then
    sudo pacman -Sy --noconfirm "${pkgs[@]}"
  elif have zypper; then
    sudo zypper install -y "${pkgs[@]}"
  elif have apk; then
    sudo apk add --no-cache "${pkgs[@]}"
  elif have brew; then
    brew install "${pkgs[@]}"
  else
    echo "❌ No supported package manager found. Install: curl nmap lynis" >&2
    exit 1
  fi
}

need_pkgs=()
have curl || need_pkgs+=(curl)
have nmap || need_pkgs+=(nmap)
have lynis || need_pkgs+=(lynis)
if [ ${#need_pkgs[@]} -gt 0 ]; then
  echo "📦 Installing missing tools: ${need_pkgs[*]}"
  pm_install "${need_pkgs[@]}"
fi

# --- Public IP ---
echo "🌐 Detecting public IP..."
PUB_IP=""
for svc in \
  "https://ifconfig.me" \
  "https://api.ipify.org" \
  "https://ipecho.net/plain"; do
  if PUB_IP="$(curl -fsS --max-time 5 "$svc" 2>/dev/null)"; then
    if [[ "$PUB_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then break; else PUB_IP=""; fi
  fi
done

if [ -z "$PUB_IP" ]; then
  echo "❌ Could not determine public IPv4. Skipping external scan."
else
  echo "✅ Public IP: $PUB_IP"
fi

# --- Nmap scan ---
NMAP_OUT="$REPORTS_DIR/nmap-${PUB_IP:-unknown}.txt"
OPEN_PORTS=0
if [ -n "$PUB_IP" ]; then
  echo "🔎 Running Nmap on $PUB_IP (top 1000 TCP ports, service detect)..."
  if nmap -Pn -T4 --top-ports 1000 -sV "$PUB_IP" -oN "$NMAP_OUT" >/dev/null 2>&1; then
    OPEN_PORTS="$(grep -E '^[0-9]+/tcp\s+open' "$NMAP_OUT" | wc -l | tr -d ' ')"
  else
    echo "⚠️ Nmap run failed; continuing."
  fi
else
  echo "ℹ️ To test the true perimeter, run Nmap from a different network against your WAN IP."
fi

# --- Lynis ---
echo "🛡️  Running Lynis local audit..."
LYNIS_SYS_LOG="/var/log/lynis.log"
LYNIS_SYS_REP="/var/log/lynis-report.dat"
# Run audit (no color) — ignore exit code (Lynis may return non-0 for warnings)
sudo lynis audit system --quiet --no-colors || true

# Copy reports into our run directory for portability
LYNIS_REP="$REPORTS_DIR/lynis-report.dat"
LYNIS_LOG="$REPORTS_DIR/lynis.log"
[ -f "$LYNIS_SYS_REP" ] && sudo cp -f "$LYNIS_SYS_REP" "$LYNIS_REP" || true
[ -f "$LYNIS_SYS_LOG" ] && sudo cp -f "$LYNIS_SYS_LOG" "$LYNIS_LOG" || true

# --- Parse Lynis report copy ---
HARDENING_IDX=0
WARN_COUNT=0
SUGG_COUNT=0
TOP_SUGGESTIONS=""
if [ -f "$LYNIS_REP" ]; then
  HARDENING_IDX="$(grep -E '^hardening_index=' "$LYNIS_REP" | head -n1 | cut -d'=' -f2 || echo 0)"
  WARN_COUNT="$(grep -cE '^warning=' "$LYNIS_REP" || echo 0)"
  SUGG_COUNT="$(grep -cE '^suggestion=' "$LYNIS_REP" || echo 0)"
  TOP_SUGGESTIONS="$(
    awk -F= '/^suggestion=/{print $2}' "$LYNIS_REP" | head -n 6 | sed 's/|/ — /' | sed 's/^/- /'
  )"
fi

# --- Composite score ---
PENALTY=0
if [ "$OPEN_PORTS" -gt 0 ]; then
  PENALTY=$(( OPEN_PORTS * 3 ))
  [ "$PENALTY" -gt 30 ] && PENALTY=30
fi
COMPOSITE=$(( HARDENING_IDX - PENALTY ))
[ "$COMPOSITE" -lt 0 ] && COMPOSITE=0
[ "$COMPOSITE" -gt 100 ] && COMPOSITE=100

# --- Output summary (console + file) ---
{
  echo
  echo "${BOLD}======== Home Server Security Summary ========${RESET}"
  printf "Date:            %s\n" "$(date -Is)"
  printf "Host:            %s\n" "$(hostname)"
  printf "Public IP:       %s\n" "${PUB_IP:-unknown}"
  printf "Nmap open ports: %s\n" "$OPEN_PORTS"
  printf "Lynis index:     %s / 100\n" "$HARDENING_IDX"
  printf "Lynis warnings:  %s\n" "$WARN_COUNT"
  printf "Lynis tips:      %s\n" "$SUGG_COUNT"
  echo   "----------------------------------------------"
  printf "${BOLD}Composite score: %s / 100${RESET}\n" "$COMPOSITE"
  echo   "----------------------------------------------"

  if [ -s "$NMAP_OUT" ]; then
    echo
    echo "${BOLD}Open ports (from Nmap on ${PUB_IP:-unknown}):${RESET}"
    grep -E '^[0-9]+/tcp\s+open' "$NMAP_OUT" | awk '{print "- " $1 "  " $3 "  " $4 " " $5 " " $6}' || true
  fi

  if [ -n "$TOP_SUGGESTIONS" ]; then
    echo
    echo "${BOLD}Top Lynis suggestions:${RESET}"
    echo "$TOP_SUGGESTIONS"
  fi

  echo
  echo "${BOLD}Files saved:${RESET}"
  [ -f "$NMAP_OUT" ] && echo " - Nmap output: $NMAP_OUT"
  [ -f "$LYNIS_LOG" ] && echo " - Lynis log:   $LYNIS_LOG"
  [ -f "$LYNIS_REP" ] && echo " - Lynis report:$LYNIS_REP"
  echo
  echo "✅ Done."
} | tee "$SUMMARY_OUT"

# also append a CSV-friendly one-liner for trend tracking
CSV="$REPORTS_DIR/summary.csv"
if [ ! -f "$CSV" ]; then echo "date,host,public_ip,open_ports,lynis_index,composite" > "$CSV"; fi
printf "%s,%s,%s,%s,%s,%s\n" \
  "$(date -Is)" "$(hostname)" "${PUB_IP:-unknown}" "$OPEN_PORTS" "$HARDENING_IDX" "$COMPOSITE" >> "$CSV"

exit 0
