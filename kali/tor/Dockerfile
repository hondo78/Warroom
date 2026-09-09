# Tor transparent-proxy gateway. The Kali container shares this container's
# network namespace (network_mode: service:tor); the iptables rules set up here
# force ALL of Kali's outbound traffic — including DNS — through Tor, and drop
# anything that would otherwise leak (LAN / direct internet).
FROM alpine:3.20

RUN apk add --no-cache tor iptables su-exec curl

COPY torrc /etc/tor/torrc
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Kali's guarded command API listens on this port inside the shared namespace.
EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=5 \
    CMD curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip | grep -q '"IsTor":true' || exit 1

ENTRYPOINT ["/entrypoint.sh"]
