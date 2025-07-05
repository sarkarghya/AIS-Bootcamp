## layers

Let's build a simple docker version. Look at test2.py. This file just downloads a few layers from a public repo and unzips them.

this by itself isn't very useful. We want to run these, and to do this, we need to be able to chroot. You can't chroot on macos for 
sad reasons, so the workaround is to use docker with --privileged

## chroot



### test2.py
Run `python test2.py` to download the layers. You now have python3.12 in extracted_python

### running the extracted image

#### in macos
Build the docker image `docker build . -t mydocker`

Then, run it `docker run --privileged -it mydocker /bin/bash`

if you are not on macos, you can try skipping the docker part. for compatibility, we will use docker for everything.

#### in linux

simply `chroot extracted_python/ /bin/bash` to get into a terminal inside the image you just downloaded.

You can see that this is actually different by running `python --version` and seeing that it is 3.12, not the version of python in the docker container that is running this chroot.

## cgroups

run with ??
```shell
docker compose up --build
```

Then, run
```shell
mkdir -p /sys/fs/cgroup/demo
cd /sys/fs/cgroup
echo "+cpu +memory +pids" > cgroup.subtree_control
cd demo
echo "1000000" > memory.max
cd /w2d2
```

Then, run inside the chroot `sh -c 'echo $$ > /sys/fs/cgroup/demo/cgroup.procs && chroot extracted_python/ /bin/sh'`
```shell
# Inside chroot
python3 -c "
data = []
for i in range(100):
    data.append('x' * 10 * 1024 * 1024)  # 10MB chunks
    print(f'Allocated {(i+1)*10}MB', flush=True)
"
```

I think there is some weird optimization happening here because it should be crashing much sooner. Test this with data.append(random) to see if it crashes sooner. you can also `echo "100M" > memory.max`

## namespaces

Namespaces provide isolation of system resources. Docker uses multiple namespace types to create container isolation.

**Where to run these commands:**
- **Linux**: Run directly in your terminal (as root or with sudo)
- **macOS**: Run inside the Docker container: `docker run --privileged -it mydocker /bin/bash`
- **All platforms**: Use docker compose: `docker compose up --build` then exec into container

**Setup required:**
1. Build Docker image: `docker build . -t mydocker`
2. Run with privileges: `docker run --privileged -it mydocker /bin/bash`
3. Extract images: `python test2.py` (this downloads the layers you'll need)

**Prerequisites:** You need to be running with privileged access to create namespaces.

### PID namespace - process isolation

Create isolated process space where processes see different PIDs:

```shell
# Check current PID
echo "Host PID: $$"

# Create PID namespace (process becomes PID 1 in namespace)
unshare --pid --fork --mount-proc /bin/sh -c 'echo "Namespace PID: $$"'
```

You should see:
```
Host PID: 1234
Namespace PID: 1
```

### Network namespace - network isolation

Create isolated network stack with no external network access:

```shell
# Check host network interfaces
ip link show

# Create network namespace (only loopback interface)
unshare --net /bin/sh -c 'ip link show'

# Test network isolation (should fail)
unshare --net /bin/sh -c 'ping -c 1 8.8.8.8 || echo "No network access"'
```

### UTS namespace - hostname isolation

Create isolated hostname that doesn't affect the host:

```shell
# Check host hostname
hostname

# Create UTS namespace and change hostname
unshare --uts /bin/sh -c 'hostname container-test && echo "New hostname: $(hostname)"'

# Verify host hostname unchanged
hostname
```

### Mount namespace - filesystem isolation

Create isolated filesystem view:

```shell
# Create mount namespace and make changes
unshare --mount /bin/sh -c '
    mkdir -p /tmp/isolated_mount
    echo "Mount namespace isolation active"
    # Changes here don't affect host
'
```

### User namespace - user/group ID isolation

Create isolated user space where you can become root:

```shell
# Check current user ID
id

# Create user namespace (become root in namespace)
unshare --user --map-root-user /bin/sh -c 'echo "Namespace user: $(id)"'
```

### All namespaces together

Create full container-like isolation:

```shell
unshare --pid --fork --mount-proc --net --uts --ipc --user --map-root-user --cgroup /bin/sh -c '
echo "=== ISOLATED CONTAINER ==="
echo "PID: $$"
echo "UID: $(id -u)"
echo "Hostname: $(hostname)"
echo "Network interfaces: $(ip link show | wc -l)"
echo "=========================="
'
```

### Combining with chroot and cgroups

Full container simulation with all isolation mechanisms:

**Run this inside the Docker container** (after `docker run --privileged -it mydocker /bin/bash` or `docker compose up --build`):

```shell
# Set up cgroup
mkdir -p /sys/fs/cgroup/container
echo "+memory" > /sys/fs/cgroup/cgroup.subtree_control
echo "100M" > /sys/fs/cgroup/container/memory.max

# Create all namespaces + cgroup + chroot
unshare --pid --fork --mount-proc --net --uts --user --map-root-user /bin/sh -c '
    echo $$ > /sys/fs/cgroup/container/cgroup.procs
    hostname my-container
    chroot extracted_python/ /bin/sh -c "
        echo Container started
        echo PID: \$\$
        echo Hostname: \$(hostname)
        echo Python version: \$(python --version)
        echo Network interfaces: \$(ip link show | wc -l)
    "
'
```

This creates a process that is:
- **PID isolated** (sees itself as PID 1)
- **Network isolated** (no external network)
- **Hostname isolated** (different hostname)
- **User isolated** (appears as root)
- **Filesystem isolated** (chroot to extracted image)
- **Memory limited** (cgroup memory limit)

## automated testing

The `test2.py` script now includes automated tests for all these namespace types:

**Run this inside the Docker container:**

```shell
python test2.py
```

**Or step by step:**
1. Build and run container: `docker run --privileged -it mydocker /bin/bash`
2. Inside container: `python test2.py`

This will run comprehensive tests showing:
1. **Layer extraction** - Downloads and extracts Docker images
2. **Chroot isolation** - Filesystem isolation testing
3. **Namespace isolation** - All 7 namespace types with verification
4. **Cgroup limits** - Memory limiting with proper enforcement
5. **Failure scenarios** - What happens when isolation blocks access

Each test verifies that the isolation is working by showing different behavior inside vs outside the isolated environment.