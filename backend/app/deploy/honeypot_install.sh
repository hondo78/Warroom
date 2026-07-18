#!/usr/bin/env bash
#
# Warroom honeypot — installer / updater / uninstaller (systemd service).
#
#   sudo WARROOM_URL=https://warroom.example.com HONEYPOT_TOKEN=hp_xxxx \
#        bash honeypot_install.sh install
#
#   sudo bash honeypot_install.sh update        # pull the latest agent + restart
#   sudo bash honeypot_install.sh uninstall     # stop + remove the service
#   sudo bash honeypot_install.sh status        # service state + recent logs
#
# Config (env vars, or the flags below):
#   WARROOM_URL          Warroom base URL            (--url,  required for install)
#   HONEYPOT_TOKEN       per-pod token hp_…          (--token, required for install)
#   HONEYPOT_TLS_VERIFY  0 = skip TLS verify         (--insecure)   self-signed proxy
#   HONEYPOT_CA          CA cert to trust            (--ca PATH)
#   HONEYPOT_BIND        listen address (0.0.0.0)    (--bind ADDR)
#
# Deploy ONLY on a dedicated, isolated host — a honeypot is meant to be reached
# by attackers. The service runs as root (needs CAP_SYS_ADMIN for fanotify and
# write access to plant decoy files across the filesystem).
set -euo pipefail

SVC="warroom-honeypot"
APP_DIR="/opt/warroom-honeypot"
AGENT="${APP_DIR}/honeypot_agent.py"
ENV_FILE="/etc/warroom-honeypot.env"
UNIT="/etc/systemd/system/${SVC}.service"

die() { echo "error: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" = "0" ] || die "run as root (use sudo)"; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed"; }

# curl that honours the same TLS knobs as the agent (self-signed Warroom proxy).
# When pinning, the one-time download trusts-on-first-use (-k); the persistent
# agent channel is then secured by the pin.
curl_tls() {
  local args=()
  if [ -n "${PIN:-}" ] || [ "${HONEYPOT_TLS_VERIFY:-1}" = "0" ]; then
    args+=(-k)
  elif [ -n "${HONEYPOT_CA:-}" ]; then
    args+=(--cacert "${HONEYPOT_CA}")
  fi
  curl "${args[@]}" "$@"
}

# SHA-256 of the Warroom server's leaf certificate (matches the agent's pin).
server_pin() {
  local hp="${WARROOM_URL#*://}"; hp="${hp%%/*}"
  local host="${hp%%:*}" port="${hp##*:}"
  [ "$port" = "$host" ] && port=443
  echo | openssl s_client -connect "${host}:${port}" -servername "${host}" 2>/dev/null \
    | openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null \
    | sed 's/^.*= *//; s/://g' | tr 'A-Z' 'a-z'
}

download_agent() {
  local url="${WARROOM_URL%/}/api/honeypot/agent/download"
  echo "downloading agent from ${url}"
  curl_tls -fsSL "${url}" -o "${AGENT}.tmp" || die "download failed (check WARROOM_URL / TLS: try --insecure for a self-signed proxy)"
  grep -q "Warroom honeypot agent" "${AGENT}.tmp" \
    || { rm -f "${AGENT}.tmp"; die "downloaded file is not the agent (wrong URL / an error page?)"; }
  mv "${AGENT}.tmp" "${AGENT}"
  chmod 0755 "${AGENT}"
}

agent_version() { grep -m1 'AGENT_VERSION *=' "${AGENT}" 2>/dev/null | sed 's/.*"\(.*\)".*/\1/' || echo "?"; }

write_env() {
  umask 077
  {
    echo "WARROOM_URL=${WARROOM_URL}"
    echo "HONEYPOT_TOKEN=${HONEYPOT_TOKEN}"
    [ -n "${PIN:-}" ] && echo "HONEYPOT_PIN=${PIN}"
    [ -n "${HONEYPOT_TLS_VERIFY:-}" ] && echo "HONEYPOT_TLS_VERIFY=${HONEYPOT_TLS_VERIFY}"
    [ -n "${HONEYPOT_CA:-}" ] && echo "HONEYPOT_CA=${HONEYPOT_CA}"
    [ -n "${HONEYPOT_BIND:-}" ] && echo "HONEYPOT_BIND=${HONEYPOT_BIND}"
  } > "${ENV_FILE}"
  chmod 600 "${ENV_FILE}"
}

write_unit() {
  local py; py="$(command -v python3)"
  cat > "${UNIT}" <<UNIT
[Unit]
Description=Warroom Honeypot Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=${ENV_FILE}
ExecStart=${py} ${AGENT}
Restart=always
RestartSec=10
# The honeypot plants decoy files anywhere and uses fanotify (CAP_SYS_ADMIN) for
# reliable file-access attribution, so it runs unrestricted by design. Deploy
# only on a dedicated, isolated host.

[Install]
WantedBy=multi-user.target
UNIT
}

cmd_install() {
  need_root; need_cmd curl; need_cmd python3; need_cmd systemctl
  [ -n "${WARROOM_URL:-}" ] || die "WARROOM_URL not set (env or --url)"
  [ -n "${HONEYPOT_TOKEN:-}" ] || die "HONEYPOT_TOKEN not set (env or --token)"
  # Resolve --pin auto to the live server cert fingerprint (trust-on-first-use).
  if [ "${PIN:-}" = "auto" ]; then
    need_cmd openssl
    PIN="$(server_pin)"
    [ -n "${PIN}" ] || die "could not fetch the server certificate to pin (is WARROOM_URL reachable?)"
    echo "pinned server cert (sha256): ${PIN}"
  fi
  mkdir -p "${APP_DIR}"
  download_agent
  write_env
  write_unit
  systemctl daemon-reload
  systemctl enable --now "${SVC}"
  echo "installed honeypot agent v$(agent_version) as service '${SVC}' and started it."
  echo "logs: journalctl -u ${SVC} -f"
  systemctl --no-pager --lines=5 status "${SVC}" || true
}

cmd_update() {
  need_root; need_cmd curl; need_cmd systemctl
  [ -f "${ENV_FILE}" ] || die "not installed (no ${ENV_FILE}) — run 'install' first"
  set -a; . "${ENV_FILE}"; set +a       # WARROOM_URL / TLS for the download
  download_agent
  systemctl restart "${SVC}"
  echo "updated to agent v$(agent_version) and restarted."
  systemctl --no-pager --lines=5 status "${SVC}" || true
}

cmd_uninstall() {
  need_root; need_cmd systemctl
  systemctl disable --now "${SVC}" 2>/dev/null || true
  rm -f "${UNIT}"
  systemctl daemon-reload
  rm -rf "${APP_DIR}"
  rm -f "${ENV_FILE}"
  echo "uninstalled service '${SVC}'."
  echo "note: any decoy files the agent planted on this host were left in place."
}

cmd_status() {
  need_cmd systemctl
  systemctl --no-pager status "${SVC}" || true
  echo; echo "recent logs:"
  journalctl -u "${SVC}" --no-pager --lines=20 2>/dev/null || true
}

cmd_pin() {
  need_cmd openssl
  if [ -z "${WARROOM_URL:-}" ] && [ -f "${ENV_FILE}" ]; then
    set -a; . "${ENV_FILE}"; set +a
  fi
  [ -n "${WARROOM_URL:-}" ] || die "WARROOM_URL not set (env, --url, or install first)"
  local fp; fp="$(server_pin)"
  [ -n "${fp}" ] || die "could not fetch the server certificate from ${WARROOM_URL}"
  echo "${fp}"
}

# --- parse: <command> [flags] -------------------------------------------------
CMD="${1:-}"; shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --url)      WARROOM_URL="$2"; shift 2 ;;
    --token)    HONEYPOT_TOKEN="$2"; shift 2 ;;
    --pin)      PIN="$2"; shift 2 ;;
    --ca)       HONEYPOT_CA="$2"; shift 2 ;;
    --bind)     HONEYPOT_BIND="$2"; shift 2 ;;
    --insecure) HONEYPOT_TLS_VERIFY="0"; shift ;;
    *) die "unknown option: $1" ;;
  esac
done

case "${CMD}" in
  install)   cmd_install ;;
  update)    cmd_update ;;
  uninstall) cmd_uninstall ;;
  status)    cmd_status ;;
  pin)       cmd_pin ;;
  *) cat >&2 <<USAGE
Warroom honeypot installer.

Usage: honeypot_install.sh <install|update|uninstall|status> [options]

  install     Install the agent as the '${SVC}' systemd service and start it.
              Needs WARROOM_URL + HONEYPOT_TOKEN (env or --url/--token).
  update      Download the latest agent from Warroom and restart the service.
  uninstall   Stop and remove the service (leaves planted decoy files).
  status      Show the service state and recent logs.
  pin         Print the Warroom server's current cert fingerprint (sha256).

Options:
  --url URL       Warroom base URL
  --token hp_…    per-pod token
  --pin auto      pin the server's current cert (secure; trust-on-first-use)
  --pin <sha256>  pin a known fingerprint (most secure; verify out-of-band)
  --ca PATH       verify against the proxy's CA cert instead of pinning
  --insecure      skip TLS verification (least secure)
  --bind ADDR     listen address (default 0.0.0.0)

Example (self-signed Warroom proxy, pinned):
  sudo WARROOM_URL=https://warroom.example.com HONEYPOT_TOKEN=hp_xxxx \\
       bash honeypot_install.sh install --pin auto
USAGE
     exit 2 ;;
esac
