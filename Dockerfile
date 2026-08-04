# rastro — batteries-included scanner image.
#
# Kali is the base rather than plain Debian because gobuster, enum4linux-ng and
# netexec are Kali packages; on debian:bookworm-slim the build fails outright.
#
#   docker build -t rastro .
#   docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
#       -v "$PWD:/out" rastro 10.0.0.5 --no-install
#
# --net=host and NET_RAW/NET_ADMIN are required: rastro's sweep is a SYN scan
# (nmap -sS), which needs raw sockets, and container NAT would otherwise rewrite
# the traffic and hide the real network.
#
# Results land in /out, the working directory — bind-mount a host directory
# there to keep them. Files are written 0600 and the run directory 0700, and the
# entrypoint hands ownership back to whoever owns the mounted /out, so the host
# user can read their own results.
FROM kalilinux/kali-rolling

# Every tool rastro knows about, so a scan never touches a package manager.
# rustscan is deliberately absent — it is not in the Kali repos, and nmap is
# the supported fallback for the sweep.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        nmap \
        curl \
        gobuster \
        enum4linux-ng \
        netexec \
        wordlists \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pyproject.toml README.md ./
COPY rastro ./rastro

# PEP 668: Kali marks its Python as externally managed. This is a dedicated
# container, so installing into the system interpreter is the right call.
RUN pip install --no-cache-dir --break-system-packages .

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

WORKDIR /out

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]
