FROM alpine:3.18

# Install Python and comprehensive network tools
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    btrfs-progs \
    iproute2 \
    iptables \
    ip6tables \
    strace \
    cgroup-tools \
    bash \
    bind-tools \
    curl \
    wget \
    ca-certificates \
    net-tools \
    tcpdump \
    nmap \
    socat \
    netcat-openbsd

# Create symlinks for python commands
RUN ln -sf /usr/bin/python3 /usr/bin/python

# Configure DNS fallback and Docker Hub hosts
RUN echo "nameserver 8.8.8.8" > /etc/resolv.conf.fallback && \
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf.fallback && \
    echo "nameserver 8.8.4.4" >> /etc/resolv.conf.fallback

# Add Docker Hub IP mappings as fallback
RUN echo "44.208.156.194  auth.docker.io" >> /etc/hosts && \
    echo "44.193.201.175  registry-1.docker.io" >> /etc/hosts && \
    echo "44.193.201.175  index.docker.io" >> /etc/hosts

# Create network initialization script
RUN echo '#!/bin/bash' > /usr/local/bin/init-network.sh && \
    echo 'if [ ! -f /etc/resolv.conf ] || [ ! -s /etc/resolv.conf ]; then' >> /usr/local/bin/init-network.sh && \
    echo '  cp /etc/resolv.conf.fallback /etc/resolv.conf' >> /usr/local/bin/init-network.sh && \
    echo 'fi' >> /usr/local/bin/init-network.sh && \
    echo 'exec "$@"' >> /usr/local/bin/init-network.sh && \
    chmod +x /usr/local/bin/init-network.sh

COPY . /w2d2
RUN pip install requests

WORKDIR /w2d2

ENTRYPOINT ["/usr/local/bin/init-network.sh"]
CMD ["python", "w2d2_solution.py"]
