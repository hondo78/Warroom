#!/bin/sh
# Force every outbound packet from this network namespace through Tor. The Kali
# container shares this namespace, so these rules govern Kali's traffic too.
#
# Leak-proofing rationale:
#   * NAT redirects all new TCP -> Tor TransPort (9040) and all DNS -> Tor
#     DNSPort (9053), so no app can pick its own route or resolver.
#   * The filter OUTPUT policy is DROP; only loopback, the Tor process's own
#     traffic (owner match) and replies to inbound connections (ESTABLISHED)
#     are allowed. A packet to a real internet/LAN address that somehow skipped
#     the NAT redirect is dropped rather than leaked.
set -e

TOR_UID=$(id -u tor)

iptables -F
iptables -t nat -F
iptables -P OUTPUT DROP

# --- NAT: transparently redirect outbound to Tor ---------------------------
# Tor's own traffic must go out untouched, or it can't reach the network.
iptables -t nat -A OUTPUT -m owner --uid-owner "$TOR_UID" -j RETURN
# DNS -> Tor DNSPort FIRST, before the loopback RETURN below — otherwise queries
# to Docker's embedded resolver (127.0.0.11, a loopback address) would bypass Tor
# and leak. Redirecting here forces every DNS lookup through the Tor network.
iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 9053
iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 9053
# Other loopback traffic stays local (the REDIRECT targets live on 127.0.0.1).
iptables -t nat -A OUTPUT -o lo -j RETURN
# Everything else (new TCP) -> Tor TransPort. Traffic to a private/LAN address
# is redirected too; Tor refuses to exit to private ranges, so it simply fails
# instead of reaching the LAN — no un-Tor'd internet or LAN access is possible.
iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040

# --- filter: default-deny with only the safe exceptions --------------------
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner "$TOR_UID" -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Redirected packets now target 127.0.0.1:{9040,9053}; allow them to reach Tor.
iptables -A OUTPUT -d 127.0.0.1/32 -j ACCEPT

echo "tor-gateway: iptables transparent-proxy rules installed (tor uid=$TOR_UID)"
mkdir -p /var/lib/tor
chown -R tor:tor /var/lib/tor
exec su-exec tor tor -f /etc/tor/torrc
