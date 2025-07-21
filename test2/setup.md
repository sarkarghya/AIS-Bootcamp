# Docker Setup Instructions

Ensure that your computer has atleast 13 GB of storage.

## Build and Run Container
```bash
# Build Docker image from current directory
docker build --network=host . -t mydocker

# Run container with host networking and required privileges
# - --network host: Use host networking
# - --privileged: Run container with extended privileges
# - --cgroupns=host: Use host's cgroup namespace
# - -it: Interactive terminal
# - -v /var/run/docker.sock:/var/run/docker.sock: Mount Docker socket
docker run --network host --privileged --cgroupns=host -it -v /var/run/docker.sock:/var/run/docker.sock mydocker /bin/sh
```

## Inside Container
```bash
# Activate Python virtual environment
. /venv/bin/activate

# Run Python file
python3 w2d2_solution.py
```

## Cleanup Docker Environment
```bash
# Stop all running containers
docker stop $(docker ps -aq)

# Remove all containers
docker rm $(docker ps -aq)

# Remove all unused containers, networks, images and volumes
docker system prune --all --volumes
```

docker system prune --all --volumes
docker build --network=host . -t mydocker
docker run --network host --privileged --cgroupns=host -it -v /var/run/docker.sock:/var/run/docker.sock mydocker /bin/sh