FROM alpine:3.18

# Install Python and system dependencies needed for container operations
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    btrfs-progs \
    iproute2 \
    iptables \
    strace \
    cgroup-tools \
    bash \
    bind-tools \
    curl \
    ca-certificates

# Create symlinks for python and pip commands
RUN ln -sf /usr/bin/python3 /usr/bin/python

# Add a hosts file entry for Docker Hub
RUN echo "44.208.156.194  auth.docker.io" >> /etc/hosts && \
    echo "44.193.201.175  registry-1.docker.io" >> /etc/hosts

COPY . /w2d2

RUN pip install requests

WORKDIR /w2d2

CMD ["python", "w2d2_solution.py"]