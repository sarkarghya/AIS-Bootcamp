FROM python:3.10-bookworm

COPY . /w2d2

# Install system dependencies needed for container operations
RUN apt-get update && apt-get install -y \
    btrfs-progs \
    iproute2 \
    iptables \
    cgroup-tools \
    strace \
    && rm -rf /var/lib/apt/lists/*

RUN pip install requests

WORKDIR /w2d2

CMD ["python", "w2d2_solution.py"]