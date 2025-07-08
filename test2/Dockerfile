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

# Create btrfs filesystem setup script
RUN mkdir -p /scripts
RUN echo '#!/bin/bash \n\
fallocate -l 10G ~/btrfs.img \n\
mkdir -p /var/docker_demo \n\
mkfs.btrfs ~/btrfs.img \n\
mount -o loop ~/btrfs.img /var/docker_demo' > /scripts/setup_btrfs.sh && \
    chmod +x /scripts/setup_btrfs.sh

# Setup for creating base image 
RUN mkdir -p ~/base-image

# Copy current directory to image
COPY . /w2d2

# Create and activate virtual environment
RUN python3 -m venv /venv

# Install Python packages in the virtual environment
# Do NOT use system pip
RUN /venv/bin/pip install --upgrade pip && \
    /venv/bin/pip install requests

# Create entrypoint script
RUN echo '#!/bin/bash \n\
# Activate virtual environment \n\
source /venv/bin/activate \n\
\n\
# Run btrfs setup script \n\
/scripts/setup_btrfs.sh \n\
\n\
# Pull and extract base image \n\
if command -v docker &> /dev/null; then \n\
  docker pull almalinux:9 || true \n\
  docker create --name temp almalinux:9 || true \n\
  # Create home directory base-image and link it to root base-image \n\
  mkdir -p ~/base-image \n\
  # Extract directly to home directory base-image \n\
  docker export temp | tar -xC ~/base-image || true \n\
  # Ensure the base-image exists and has proper permissions \n\
  chmod -R 755 ~/base-image \n\
  # Create symlink for compatibility \n\
  ln -sf ~/base-image /base-image \n\
  docker rm temp || true \n\
  # Print directory for debugging \n\
  echo "Base image extracted to:" \n\
  ls -la ~/base-image \n\
else \n\
  # If docker is not available, use our pre-created minimal base image \n\
  echo "Using pre-created minimal base image" \n\
  ls -la ~/base-image \n\
fi \n\
\n\
# Make sure essential directories exist in the base image \n\
# mkdir -p ~/base-image/bin ~/base-image/etc ~/base-image/lib ~/base-image/lib64 ~/base-image/usr/bin ~/base-image/var \n\
\n\
# Make sure yum exists in the base image \n\
if [ ! -f ~/base-image/usr/bin/yum ] && [ -f /usr/bin/yum ]; then \n\
  mkdir -p ~/base-image/usr/bin \n\
  cp /usr/bin/yum ~/base-image/usr/bin/ \n\
  # Copy necessary dependencies \n\
  mkdir -p ~/base-image/usr/lib ~/base-image/etc/yum ~/base-image/etc/yum.repos.d \n\
  cp -r /etc/yum* ~/base-image/etc/ 2>/dev/null || true \n\
  echo "[main]\\nkeepcache=0\\ngpgcheck=0" > ~/base-image/etc/yum.conf \n\
  echo "[baseos]\\nname=AlmaLinux 9 - BaseOS\\nbaseurl=http://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/\\nenabled=1\\ngpgcheck=0" > ~/base-image/etc/yum.repos.d/almalinux.repo \n\
fi \n\
\n\
# Execute the Python script \n\
' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

WORKDIR /w2d2
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
