FROM ubuntu:24.04

# Update package repositories
RUN apt-get update

# Install Python and required packages
RUN apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-full \
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
    libtool

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

# Copy current directory to image
COPY . /w2d2

# Create and activate virtual environment
RUN python3 -m venv /venv

# Install Python packages in the virtual environment
# Do NOT use system pip
RUN /venv/bin/pip install --upgrade pip && \
    /venv/bin/pip install requests

RUN source /venv/bin/activate
WORKDIR /w2d2
