FROM ubuntu:22.04

# Install Python and system dependencies needed for container operations
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    btrfs-progs \
    iproute2 \
    iptables \
    cgroup-tools \
    strace \
    && rm -rf /var/lib/apt/lists/*

# Create symlinks for python and pip commands
RUN ln -sf /usr/bin/python3 /usr/bin/python && \
    ln -sf /usr/bin/pip3 /usr/bin/pip

COPY . /w2d2

RUN pip install requests

WORKDIR /w2d2

CMD ["python", "w2d2_solution.py"]