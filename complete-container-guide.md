# Complete Container Guide - Linux Edition

## Overview

This guide covers building a simple Docker-like container system from scratch, including:
- Downloading and extracting Docker image layers
- Using chroot to run isolated processes
- Managing resource limits with cgroups
- Testing memory allocation limits

## Part 1: Docker Layer Extraction

### The Python Script (test2.py)

Our main script downloads Docker image layers and provides functionality for chroot and cgroup management:

```python
#!/usr/bin/env python3

# %% Imports
import requests
import tarfile
import json
import sys
import os
import platform
from io import BytesIO

# %% Architecture selection
# For macOS on Apple Silicon (M1/M2/M3)
TARGET_ARCH = "arm64"
TARGET_VARIANT = "v8"

print(f"Detected architecture: {TARGET_ARCH} {TARGET_VARIANT if TARGET_VARIANT else ''}")
# For x86/Intel machines, uncomment the following:
# TARGET_ARCH = "amd64"
# TARGET_VARIANT = None

# %% Main function
def pull_layers(image_ref, output_dir):
    """
    Pull and extract Docker image layers for a specific architecture

    Args:
        image_ref: Can be:
            - Full URL: https://registry-1.docker.io/v2/library/hello-world/manifests/latest
            - Docker Hub format: hello-world:latest or library/hello-world:latest
            - Other registry: gcr.io/google-containers/pause:latest
        output_dir: Directory to extract layers to
    """

    # Parse image reference
    if image_ref.startswith('http'):
        # Full URL provided
        parts = image_ref.replace('https://', '').replace('http://', '').split('/')
        registry = parts[0]
        if '/manifests/' in image_ref:
            # Extract image and tag from URL
            image_parts = '/'.join(parts[2:]).split('/manifests/')
            image = image_parts[0]
            tag = image_parts[1]
        else:
            image = '/'.join(parts[1:-1])
            tag = parts[-1] if ':' in parts[-1] else 'latest'
    else:
        # Docker image format (e.g., "hello-world:latest" or "gcr.io/project/image:tag")
        if '/' in image_ref and image_ref.split('/')[0].count('.') > 0:
            # Custom registry (e.g., gcr.io/project/image)
            parts = image_ref.split('/', 1)
            registry = parts[0]
            image_and_tag = parts[1]
        else:
            # Docker Hub
            registry = 'registry-1.docker.io'
            image_and_tag = image_ref
            if '/' not in image_and_tag:
                image_and_tag = f"library/{image_and_tag}"

        if ':' in image_and_tag:
            image, tag = image_and_tag.rsplit(':', 1)
        else:
            image = image_and_tag
            tag = 'latest'

    print(f"Registry: {registry}")
    print(f"Image: {image}")
    print(f"Tag: {tag}")
    print(f"Target architecture: {TARGET_ARCH}{f' variant {TARGET_VARIANT}' if TARGET_VARIANT else ''}")

    # Create output directory
    # bash: mkdir -p ./extracted
    os.makedirs(output_dir, exist_ok=True)

    # Get auth token for Docker Hub if needed
    headers = {}
    if registry == 'registry-1.docker.io':
        # bash: curl "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/hello-world:pull"
        token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
        token_resp = requests.get(token_url)
        token_resp.raise_for_status()
        token = token_resp.json()['token']
        headers['Authorization'] = f'Bearer {token}'

    # Step 1: Get manifest list (without Accept header to get the index)
    # bash: curl -L https://registry-1.docker.io/v2/library/hello-world/manifests/latest
    manifest_list_url = f"https://{registry}/v2/{image}/manifests/{tag}"
    print(f"\nFetching manifest list from: {manifest_list_url}")

    resp = requests.get(manifest_list_url, headers=headers)
    resp.raise_for_status()
    manifest_list = resp.json()

    # Step 2: Find the manifest for our target architecture
    # bash: cat manifest-list.json | jq '.manifests[] | select(.platform.architecture=="arm64")'
    target_manifest = None
    for manifest in manifest_list.get('manifests', []):
        platform = manifest.get('platform', {})
        if platform.get('architecture') == TARGET_ARCH:
            # Check variant if specified
            if TARGET_VARIANT:
                if platform.get('variant') == TARGET_VARIANT:
                    target_manifest = manifest
                    break
            else:
                # No variant specified, take the first match
                target_manifest = manifest
                break

    if not target_manifest:
        print(
            f"\nError: No manifest found for architecture {TARGET_ARCH}{f' variant {TARGET_VARIANT}' if TARGET_VARIANT else ''}")
        print("\nAvailable architectures:")
        for manifest in manifest_list.get('manifests', []):
            platform = manifest.get('platform', {})
            print(f"  - {platform.get('architecture')} {platform.get('variant', '')}")
        return

    manifest_digest = target_manifest['digest']
    print(f"\nFound manifest for {TARGET_ARCH}: {manifest_digest}")

    # Step 3: Get the actual manifest using the digest
    # bash: curl -L -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
    #       https://registry-1.docker.io/v2/library/hello-world/manifests/sha256:xxx
    manifest_url = f"https://{registry}/v2/{image}/manifests/{manifest_digest}"
    headers['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json'

    print(f"Fetching manifest from: {manifest_url}")
    resp = requests.get(manifest_url, headers=headers)
    resp.raise_for_status()
    manifest = resp.json()

    # Manifest structure example:
    # {
    #   "schemaVersion": 2,
    #   "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    #   "config": { "digest": "sha256:xxx", "size": 123 },
    #   "layers": [
    #     { "digest": "sha256:yyy", "size": 456 },
    #     { "digest": "sha256:zzz", "size": 789 }
    #   ]
    # }

    print(f"\nManifest type: {manifest.get('mediaType', 'unknown')}")
    print(f"Number of layers: {len(manifest.get('layers', []))}")

    # Step 4: Download and extract layers in order
    for i, layer in enumerate(manifest.get('layers', [])):
        digest = layer['digest']
        size = layer.get('size', 0)
        print(f"\nProcessing layer {i + 1}/{len(manifest['layers'])}: {digest} ({size} bytes)")

        # Download layer blob
        # bash: curl -L https://registry-1.docker.io/v2/library/hello-world/blobs/sha256:xxx > layer.tar.gz
        blob_url = f"https://{registry}/v2/{image}/blobs/{digest}"
        blob_resp = requests.get(blob_url, headers=headers, stream=True)
        blob_resp.raise_for_status()

        # Extract layer (layers are gzipped tarballs)
        # bash: tar -xzf layer.tar.gz -C ./extracted
        print(f"  Extracting to {output_dir}...")
        with tarfile.open(fileobj=BytesIO(blob_resp.content), mode='r:gz') as tar:
            tar.extractall(output_dir)

    print(f"\n✓ Extracted {len(manifest.get('layers', []))} layers to {output_dir}")
    print(f"  Architecture: {TARGET_ARCH}{f' variant {TARGET_VARIANT}' if TARGET_VARIANT else ''}")


# %% Image downloads
# Test with Docker Hub hello-world image:
image_ref = "alpine:latest"
output_dir = "./extracted_alpine"
pull_layers(image_ref, output_dir)

# Test with Docker Hub hello-world image:
image_ref = "python:3.12-alpine"
output_dir = "./extracted_python"
pull_layers(image_ref, output_dir)
```

### Chroot functionality

```python
# %% Chroot functionality
def run_chroot(chroot_dir, command=None):
    """
    Run a command in a chrooted environment
    
    Args:
        chroot_dir: Directory to chroot into
        command: Command to run (default: /bin/sh)
    """
    import subprocess
    
    if command is None:
        command = ['/bin/sh']
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
    
    print(f"Running chroot {chroot_dir} with command: {' '.join(command)}")
    
    try:
        result = subprocess.run(['chroot', chroot_dir] + command, 
                              capture_output=True, text=True, timeout=30)
        print(f"Exit code: {result.returncode}")
        if result.stdout:
            print(f"stdout:\n{result.stdout}")
        if result.stderr:
            print(f"stderr:\n{result.stderr}")
        return result
    except subprocess.TimeoutExpired:
        print("Command timed out after 30 seconds")
        return None
    except Exception as e:
        print(f"Error running chroot: {e}")
        return None


def test_chroot_python():
    """Test that chrooted Python is version 3.12"""
    return run_chroot("./extracted_python", "python --version")
```

### Cgroup management functions

```python
# %% Cgroup management functions
def create_cgroup(cgroup_name, memory_limit=None, cpu_limit=None):
    """
    Create a cgroup with specified limits
    
    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
        cpu_limit: CPU limit (not implemented yet)
    """
    import subprocess
    import os
    
    cgroup_path = f"/sys/fs/cgroup/{cgroup_name}"
    
    # Create cgroup directory
    os.makedirs(cgroup_path, exist_ok=True)
    print(f"Created cgroup directory: {cgroup_path}")
    
    # Enable controllers in parent cgroup
    try:
        with open("/sys/fs/cgroup/cgroup.subtree_control", "w") as f:
            f.write("+cpu +memory +pids")
        print("Enabled cgroup controllers")
    except Exception as e:
        print(f"Warning: Could not enable controllers: {e}")
    
    # Set memory limit if specified
    if memory_limit:
        memory_max_path = f"{cgroup_path}/memory.max"
        try:
            with open(memory_max_path, "w") as f:
                f.write(str(memory_limit))
            print(f"Set memory limit to {memory_limit}")
        except Exception as e:
            print(f"Error setting memory limit: {e}")
    
    return cgroup_path


def add_process_to_cgroup(cgroup_name, pid=None):
    """
    Add a process to a cgroup
    
    Args:
        cgroup_name: Name of the cgroup
        pid: Process ID (default: current process)
    """
    import os
    
    if pid is None:
        pid = os.getpid()
    
    cgroup_procs_path = f"/sys/fs/cgroup/{cgroup_name}/cgroup.procs"
    
    try:
        with open(cgroup_procs_path, "w") as f:
            f.write(str(pid))
        print(f"Added process {pid} to cgroup {cgroup_name}")
        return True
    except Exception as e:
        print(f"Error adding process to cgroup: {e}")
        return False


def run_in_cgroup_chroot(cgroup_name, chroot_dir, command=None, memory_limit="100M"):
    """
    Run a command in both a cgroup and chroot environment
    
    Args:
        cgroup_name: Name of the cgroup to create/use
        chroot_dir: Directory to chroot into
        command: Command to run
        memory_limit: Memory limit for the cgroup
    """
    import subprocess
    import os
    
    # Create cgroup
    create_cgroup(cgroup_name, memory_limit=memory_limit)
    
    if command is None:
        command = ['/bin/sh']
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
    
    # Create a shell script that adds the process to cgroup then chroots
    script = f"""
    echo $$ > /sys/fs/cgroup/{cgroup_name}/cgroup.procs
    chroot {chroot_dir} {' '.join(command)}
    """
    
    print(f"Running in cgroup {cgroup_name} with chroot {chroot_dir}")
    
    try:
        result = subprocess.run(['sh', '-c', script], 
                              capture_output=True, text=True, timeout=60)
        print(f"Exit code: {result.returncode}")
        if result.stdout:
            print(f"stdout:\n{result.stdout}")
        if result.stderr:
            print(f"stderr:\n{result.stderr}")
        return result
    except subprocess.TimeoutExpired:
        print("Command timed out after 60 seconds")
        return None
    except Exception as e:
        print(f"Error running command: {e}")
        return None


def test_memory_allocation(cgroup_name="demo", memory_limit="100M"):
    """
    Test memory allocation in a cgroup with chroot
    This should trigger the memory limit and cause the process to be killed
    """
    python_code = '''
import random
data = []
for i in range(100):
    # Use random data to prevent optimization
    data.append(str(random.random()) * 10 * 1024 * 1024)  # 10MB chunks
    print(f"Allocated {(i+1)*10}MB", flush=True)
'''
    
    return run_in_cgroup_chroot(
        cgroup_name=cgroup_name,
        chroot_dir="./extracted_python",
        command=f"python3 -c '{python_code}'",
        memory_limit=memory_limit
    )
```

### Test functions

```python
# %% Test basic chroot functionality
print("Testing chroot Python version:")
test_chroot_python()

# %% Test memory allocation with 100M limit - should crash
print("Testing memory allocation with 100M limit (should crash):")
test_memory_allocation(cgroup_name="demo", memory_limit="1000000")

# %% Test with 1GB limit - should work longer
print("Testing memory allocation with 1GB limit:")
test_memory_allocation(cgroup_name="demo2", memory_limit="1000M")
```

## Part 2: Docker Setup (Optional for Linux)

### Building Docker Image

Since you're on Linux, you can skip the Docker setup and run chroot directly. However, if you want to use Docker:

```bash
# Build the docker image
docker build . -t mydocker

# Run with privileged mode (needed for chroot)
docker run --privileged -it mydocker /bin/bash
```

### Docker Compose Setup

For cgroup testing with Docker:

```bash
# Run with docker compose
docker compose up --build
```

## Part 3: Running the Container System

### Step 1: Download Layers

Run the Python script to download Docker image layers:

```bash
python test2.py
```

This will:
- Download Alpine Linux layers to `./extracted_alpine`
- Download Python 3.12 Alpine layers to `./extracted_python`

### Step 2: Basic Chroot Testing

**Linux users can run this directly without Docker:**

```bash
# Test that chroot works and shows Python 3.12
sudo chroot extracted_python/ python --version
```

You should see Python 3.12.x, which is different from your host Python version.

### Step 3: Cgroup Setup and Testing

**Linux users can run these commands directly:**

```bash
# Create cgroup directory
sudo mkdir -p /sys/fs/cgroup/demo

# Navigate to cgroup directory
cd /sys/fs/cgroup

# Enable controllers
sudo sh -c 'echo "+cpu +memory +pids" > cgroup.subtree_control'

# Set memory limit
cd demo
sudo sh -c 'echo "100M" > memory.max'

# Return to working directory
cd /path/to/your/project
```

### Step 4: Testing Memory Limits

Run a process in the cgroup and chroot environment:

```bash
# Add current shell to cgroup and chroot
sudo sh -c 'echo $$ > /sys/fs/cgroup/demo/cgroup.procs && chroot extracted_python/ python3 -c "
import random
data = []
for i in range(100):
    data.append(str(random.random()) * 10 * 1024 * 1024)  # 10MB chunks
    print(f\"Allocated {(i+1)*10}MB\", flush=True)
"'
```

This should crash when it hits the 100MB memory limit.

## Part 4: Advanced Testing

### Testing with different memory limits

```bash
# Test with 1GB limit (should work longer)
sudo sh -c 'echo "1000M" > /sys/fs/cgroup/demo/memory.max'

# Or create a new cgroup for testing
sudo mkdir -p /sys/fs/cgroup/demo2
sudo sh -c 'echo "1000M" > /sys/fs/cgroup/demo2/memory.max'
```

### Notes on Memory Optimization

The original comment mentions that Python might be optimizing memory allocation. To test this more effectively:

1. Use `random.random()` in the data to prevent optimization
2. Use smaller memory limits like `"100M"` instead of raw bytes
3. The process should be killed by the OOM killer when it exceeds the limit

## Part 5: Understanding the Architecture

### What's happening:

1. **Layer Download**: The script downloads Docker image layers from Docker Hub
2. **Layer Extraction**: Each layer is a gzipped tarball that gets extracted
3. **Chroot Environment**: We change the root directory to the extracted filesystem
4. **Cgroup Limits**: We set resource limits (memory, CPU) for processes
5. **Process Isolation**: Combining chroot + cgroups gives us basic container functionality

### Key differences from Docker:

- No network isolation (no network namespaces)
- No PID isolation (no PID namespaces) 
- No user isolation (no user namespaces)
- No mount isolation (no mount namespaces)

This is a simplified container implementation focusing on filesystem isolation (chroot) and resource limits (cgroups).

## Troubleshooting

### Common Issues:

1. **Permission Denied**: Run with `sudo` for chroot and cgroup operations
2. **Cgroup not found**: Make sure you're on a system with cgroup v2 support
3. **Architecture mismatch**: Adjust `TARGET_ARCH` in the script for your CPU architecture
4. **Memory limit not working**: Check that the cgroup controllers are enabled

### Architecture Selection:

```python
# For ARM64 (Apple Silicon, ARM servers)
TARGET_ARCH = "arm64"
TARGET_VARIANT = "v8"

# For x86_64 (Intel/AMD)
TARGET_ARCH = "amd64"
TARGET_VARIANT = None
```

## Summary

This guide demonstrates building a basic container system by:
1. Downloading real Docker image layers
2. Using chroot for filesystem isolation
3. Using cgroups for resource limits
4. Testing memory allocation limits

The combination of chroot + cgroups provides the foundation for container technology, though production systems like Docker add many more features for security, networking, and management. 