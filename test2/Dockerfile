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
    bash

# Create symlinks for python and pip commands
RUN ln -sf /usr/bin/python3 /usr/bin/python

COPY . /w2d2

RUN pip install requests

WORKDIR /w2d2

CMD ["python", "w2d2_solution.py"]