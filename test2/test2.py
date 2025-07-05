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
import platform

# Automatic architecture detection in 3 lines
TARGET_ARCH, TARGET_VARIANT = {
    'x86_64': ('amd64', None), 'amd64': ('amd64', None),
    'arm64': ('arm64', 'v8'), 'aarch64': ('arm64', 'v8'),
    'armv7l': ('arm', 'v7'), 'armv6l': ('arm', 'v6')
}.get(platform.machine().lower(), ('amd64', None))

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


# %%
# Test with Docker Hub hello-world image:
image_ref = "alpine:latest"
output_dir = "./extracted_alpine"
pull_layers(image_ref, output_dir)
# %%
# Test with Docker Hub hello-world image:
image_ref = "python:3.12-alpine"
output_dir = "./extracted_python"
pull_layers(image_ref, output_dir)


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
    
    print(f"🔧 DEBUG: Attempting to create cgroup: {cgroup_path}")
    
    try:
        # Create cgroup directory
        os.makedirs(cgroup_path, exist_ok=True)
        print(f"✅ DEBUG: Created cgroup directory: {cgroup_path}")
        
        # Verify directory exists
        if os.path.exists(cgroup_path):
            print(f"✅ DEBUG: Cgroup directory confirmed to exist")
        else:
            print(f"❌ DEBUG: Cgroup directory does not exist after creation!")
            return None
        
        # Enable controllers in parent cgroup
        try:
            with open("/sys/fs/cgroup/cgroup.subtree_control", "w") as f:
                f.write("+cpu +memory +pids")
            print("✅ DEBUG: Enabled cgroup controllers")
        except Exception as e:
            print(f"⚠️  DEBUG: Could not enable controllers: {e}")
        
        # Set memory limit if specified
        if memory_limit:
            memory_max_path = f"{cgroup_path}/memory.max"
            print(f"🔧 DEBUG: Setting memory limit in {memory_max_path}")
            try:
                with open(memory_max_path, "w") as f:
                    f.write(str(memory_limit))
                print(f"✅ DEBUG: Set memory limit to {memory_limit}")
                
                # Verify memory limit was set
                with open(memory_max_path, "r") as f:
                    actual_limit = f.read().strip()
                print(f"✅ DEBUG: Memory limit verified: {actual_limit}")
            except Exception as e:
                print(f"❌ DEBUG: Error setting memory limit: {e}")
                return None
        
        return cgroup_path
        
    except OSError as e:
        print(f"❌ DEBUG: OSError creating cgroup: {e}")
        if e.errno == 30:  # Read-only file system
            print("❌ DEBUG: /sys/fs/cgroup is read-only!")
        return None
    except Exception as e:
        print(f"❌ DEBUG: Unexpected error creating cgroup: {e}")
        return None


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
    
    print(f"🚀 DEBUG: Starting {cgroup_name} test...")
    
    # Create cgroup
    cgroup_path = create_cgroup(cgroup_name, memory_limit=memory_limit)
    
    if not cgroup_path:
        print("❌ DEBUG: Cgroup creation failed, cannot proceed")
        return None
    
    if command is None:
        command = ['/bin/sh']
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
    
    # Create a shell script that adds the process to cgroup then chroots
    script = f"""
    echo "DEBUG: Shell script PID: $$"
    echo "DEBUG: Adding process to cgroup..."
    echo $$ > /sys/fs/cgroup/{cgroup_name}/cgroup.procs
    
    echo "DEBUG: Verifying process is in cgroup..."
    if grep -q "$$" /sys/fs/cgroup/{cgroup_name}/cgroup.procs; then
        echo "DEBUG: Process successfully added to cgroup"
    else
        echo "DEBUG: ERROR - Process not in cgroup!"
        exit 1
    fi
    
    echo "DEBUG: Current cgroup info:"
    cat /proc/self/cgroup
    
    echo "DEBUG: Memory limit info:"
    cat /sys/fs/cgroup/{cgroup_name}/memory.max
    
    echo "DEBUG: Starting chroot..."
    chroot {chroot_dir} {' '.join(command)}
    """
    
    print(f"🔧 DEBUG: Running in cgroup {cgroup_name} with chroot {chroot_dir}")
    print(f"🔧 DEBUG: Memory limit: {memory_limit}")
    
    try:
        # Use shorter timeout to see the kill faster
        result = subprocess.run(['sh', '-c', script], 
                              capture_output=True, text=True, timeout=30)
        print(f"🔧 DEBUG: Exit code: {result.returncode}")
        if result.returncode == 137:
            print("🎯 DEBUG: Exit code 137 = SIGKILL - Process killed by OOM!")
        elif result.returncode == 9:
            print("🎯 DEBUG: Exit code 9 = SIGKILL - Process killed by system!")
        elif result.returncode != 0:
            print(f"🔧 DEBUG: Non-zero exit code: {result.returncode}")
            
        if result.stdout:
            print(f"🔧 DEBUG: stdout:\n{result.stdout}")
        if result.stderr:
            print(f"🔧 DEBUG: stderr:\n{result.stderr}")
        return result
    except subprocess.TimeoutExpired:
        print("⚠️  DEBUG: Command timed out after 30 seconds")
        print("This might mean the memory limit isn't working properly")
        return None
    except Exception as e:
        print(f"❌ DEBUG: Error running command: {e}")
        return None


def test_memory_allocation(cgroup_name="demo", memory_limit="100M"):
    """
    Test memory allocation in a cgroup with chroot
    This should trigger the memory limit and cause the process to be killed
    """
    python_code = '''
import random
import sys
import os
import time

print(f"🔥 MEMORY ALLOCATION TEST - PID: {os.getpid()}")
print(f"Attempting to allocate memory until limit is hit...")

data = []
allocated_mb = 0

try:
    for i in range(200):  # Try to allocate 2GB total
        # Use random data to prevent optimization
        chunk = str(random.random()) * 1024 * 1024  # 1MB chunks
        data.append(chunk)
        allocated_mb += 1
        
        print(f"✅ Allocated {allocated_mb}MB", flush=True)
        
        # Add small delay to see progress
        time.sleep(0.1)
        
        # Check memory usage occasionally
        if allocated_mb % 10 == 0:
            print(f"🔥 {allocated_mb}MB allocated - still running!", flush=True)
            
except MemoryError:
    print(f"❌ MemoryError at {allocated_mb}MB - Python ran out of memory")
except Exception as e:
    print(f"❌ Error at {allocated_mb}MB: {e}")
    
print(f"🎯 Memory test completed. Total allocated: {allocated_mb}MB")
'''
    
    return run_in_cgroup_chroot(
        cgroup_name=cgroup_name,
        chroot_dir="./extracted_python",
        command=f"python3 -c '{python_code}'",
        memory_limit=memory_limit
    )


# %% Test basic chroot functionality
print("Testing chroot Python version:")
test_chroot_python()

# %% Test memory allocation with 1MB limit - should crash immediately
print("\n" + "="*60)
print("🧪 Testing memory allocation with 1MB limit (should crash immediately):")
print("="*60)
test_memory_allocation(cgroup_name="demo", memory_limit="1048576")  # 1MB in bytes

# %% Test with 10MB limit - should crash after a few allocations
print("\n" + "="*60)
print("🧪 Testing memory allocation with 10MB limit:")
print("="*60)
test_memory_allocation(cgroup_name="demo2", memory_limit="10485760")  # 10MB in bytes
