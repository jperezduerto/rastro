# rastro — batteries-included scanner image.
#
# The image ships the scanning tools preinstalled, so rastro never needs to
# install anything at runtime. Run it with --no-install to make that explicit.
#
#   docker build -t rastro .
#   docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
#       -v "$PWD:/out" rastro 10.0.0.5 --no-install
#
# --net=host and NET_RAW/NET_ADMIN are required: rastro's sweep is a SYN scan
# (nmap -sS), which needs raw sockets, and container NAT would otherwise
# rewrite the traffic and hide the real network.
#
# Results land in /out, which is the container's working directory — bind-mount
# a host directory there to keep them.
FROM debian:bookworm-slim

# nmap is the only required tool; the rest are optional enumerators that rastro
# records in `skipped` when absent. They are baked in so a scan never has to
# touch a package manager.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        nmap \
        curl \
        gobuster \
        enum4linux-ng \
        dnsutils \
        ca-certificates \
        wordlists \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pyproject.toml README.md ./
COPY rastro ./rastro

# PEP 668: Debian marks its Python as externally managed. This is a dedicated
# container, so installing into the system interpreter is correct here.
RUN pip install --no-cache-dir --break-system-packages .

WORKDIR /out

ENTRYPOINT ["rastro"]
CMD ["--help"]
