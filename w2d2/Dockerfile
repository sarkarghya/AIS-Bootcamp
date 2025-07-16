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
    libtool\
    iputils-ping

# Create symlinks for python commands
RUN ln -sf /usr/bin/python3 /usr/bin/python

# Make resolv.conf immutable to prevent overwrites
RUN chattr +i /etc/resolv.conf 2>/dev/null || true

# Copy current directory to image
COPY . /w2d2

# Create and activate virtual environment
RUN python3 -m venv /venv

RUN . /venv/bin/activate

# Install Python packages in the virtual environment
# Do NOT use system pip
RUN /venv/bin/pip install --upgrade pip && \
    /venv/bin/pip install requests

WORKDIR /w2d2