FROM ubuntu:24.04

# Update package repositories
RUN apt-get update

# Install Python and required packages
RUN apt-get install -y \
    python3 \
    python3-pip \
    btrfs-progs \
    iproute2 \
    iptables \
    strace \
    cgroup-tools \
    bash \
    curl \
    ca-certificates \
    dnsutils \
    docker.io \
    git \
    autoconf \
    automake \
    gettext \
    autopoint \
    libtool \
    python3-venv

# Create symlinks for python commands
RUN ln -sf /usr/bin/python3 /usr/bin/python

# Force DNS configuration - this overrides host DNS completely
RUN echo "nameserver 8.8.8.8" > /etc/resolv.conf && \
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf && \
    echo "nameserver 8.8.4.4" >> /etc/resolv.conf

# Add static host entries as backup
RUN echo "44.208.156.194  auth.docker.io" >> /etc/hosts && \
    echo "44.193.201.175  registry-1.docker.io" >> /etc/hosts && \
    echo "44.193.201.175  index.docker.io" >> /etc/hosts

# Make resolv.conf immutable to prevent overwrites
RUN chattr +i /etc/resolv.conf 2>/dev/null || true

# Create btrfs filesystem setup script
RUN mkdir -p /scripts
RUN echo '#!/bin/bash \n\
fallocate -l 10G /btrfs.img \n\
mkdir -p /var/docker_demo \n\
mkfs.btrfs /btrfs.img \n\
mount -o loop /btrfs.img /var/docker_demo' > /scripts/setup_btrfs.sh && \
    chmod +x /scripts/setup_btrfs.sh

# Setup for creating base image 
RUN mkdir -p /base-image

# Create entrypoint script
RUN echo '#!/bin/bash \n\
# Run btrfs setup script \n\
/scripts/setup_btrfs.sh \n\
\n\
# Pull and extract base image \n\
if command -v docker &> /dev/null; then \n\
  docker pull almalinux:9 || true \n\
  docker create --name temp almalinux:9 || true \n\
  docker export temp | tar -xC /base-image || true \n\
  docker rm temp || true \n\
fi \n\
\n\
' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

# Copy current directory to image
COPY . /w2d2
RUN pip install requests

WORKDIR /w2d2
ENTRYPOINT ["/entrypoint.sh"]
