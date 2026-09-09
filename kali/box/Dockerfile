# Kali box reachable ONLY through the Tor gateway (see docker-compose:
# network_mode "service:tor"). It exposes a small, guarded command API — never a
# raw shell — that the Warroom backend calls over the internal network.
FROM kalilinux/kali-rolling

# A curated recon toolset. Deliberately NOT the full kali metapackages: only
# tools that make sense for anonymized OSINT/recon over Tor.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    python3 \
    nmap \
    whois \
    dnsutils \
    curl \
    wget \
    ncat \
    whatweb \
    nikto \
    sslscan \
    wafw00f \
    dnsrecon \
    && rm -rf /var/lib/apt/lists/*

COPY kali_api.py /opt/kali_api.py

# Runs as a normal user; nmap SYN/OS scans that need root will simply fail,
# which is fine — TCP connect scans work unprivileged.
RUN useradd -m -u 1000 kaliapi
USER kaliapi

CMD ["python3", "/opt/kali_api.py"]
