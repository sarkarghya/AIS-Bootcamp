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
        cpu_limit: CPU limit as percentage (e.g., 50 for 50% of one CPU core)
    
    Returns:
        cgroup_path if successful, None if failed
    """
    import subprocess
    import os
    
    cgroup_path = f"/sys/fs/cgroup/{cgroup_name}"
    
    try:
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
        
        # Set CPU limit if specified
        if cpu_limit:
            cpu_max_path = f"{cgroup_path}/cpu.max"
            try:
                # cpu.max format: "quota period"
                # For example, 50% of one CPU = "50000 100000" (50ms out of 100ms)
                quota = int(cpu_limit * 1000)  # Convert percentage to microseconds
                period = 100000  # 100ms period
                with open(cpu_max_path, "w") as f:
                    f.write(f"{quota} {period}")
                print(f"Set CPU limit to {cpu_limit}% of one core")
            except Exception as e:
                print(f"Error setting CPU limit: {e}")
        
        return cgroup_path
        
    except OSError as e:
        print(f"ERROR: Cannot create cgroup {cgroup_name}: {e}")
        print("This is likely because:")
        print("1. You don't have root privileges")
        print("2. The cgroup filesystem is read-only")
        print("3. cgroups v2 is not available")
        print("Continuing without cgroup limits...")
        return None
    except Exception as e:
        print(f"Unexpected error creating cgroup: {e}")
        return None


def safe_run_command(command, timeout=60, description="command"):
    """
    Safely run a command with timeout and error handling
    
    Args:
        command: Command to run (list or string)
        timeout: Timeout in seconds
        description: Description for logging
    
    Returns:
        result object or None if failed
    """
    import subprocess
    import signal
    import os
    
    print(f"Running {description} with timeout {timeout}s...")
    
    try:
        if isinstance(command, str):
            result = subprocess.run(command, shell=True, capture_output=True, 
                                  text=True, timeout=timeout)
        else:
            result = subprocess.run(command, capture_output=True, 
                                  text=True, timeout=timeout)
        
        print(f"Exit code: {result.returncode}")
        if result.stdout:
            print(f"stdout:\n{result.stdout}")
        if result.stderr:
            print(f"stderr:\n{result.stderr}")
        return result
        
    except subprocess.TimeoutExpired:
        print(f"⚠️  {description} timed out after {timeout} seconds - killing process")
        return None
    except Exception as e:
        print(f"❌ Error running {description}: {e}")
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


def run_in_cgroup_chroot(cgroup_name, chroot_dir, command=None, memory_limit="100M", cpu_limit=None):
    """
    Run a command in both a cgroup and chroot environment
    
    Args:
        cgroup_name: Name of the cgroup to create/use
        chroot_dir: Directory to chroot into
        command: Command to run
        memory_limit: Memory limit for the cgroup
        cpu_limit: CPU limit as percentage
    """
    import subprocess
    import os
    
    print(f"🚀 Starting {cgroup_name} test...")
    
    # Try to create cgroup with both memory and CPU limits
    cgroup_path = create_cgroup(cgroup_name, memory_limit=memory_limit, cpu_limit=cpu_limit)
    
    if command is None:
        command = ['/bin/sh']
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
    
    if cgroup_path:
        # Create a shell script that adds the process to cgroup then chroots
        script = f"""
        echo $$ > /sys/fs/cgroup/{cgroup_name}/cgroup.procs
        chroot {chroot_dir} {' '.join(command)}
        """
        print(f"Running in cgroup {cgroup_name} with chroot {chroot_dir}")
        return safe_run_command(script, timeout=30, description=f"cgroup+chroot {cgroup_name}")
    else:
        # Fallback: run without cgroup (just chroot)
        print(f"⚠️  Running WITHOUT cgroup limits (just chroot) in {chroot_dir}")
        fallback_command = f"chroot {chroot_dir} {' '.join(command)}"
        return safe_run_command(fallback_command, timeout=30, description=f"chroot-only {cgroup_name}")


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


def test_cpu_stress(cgroup_name="cpu_demo", cpu_limit=10):
    """
    Test CPU stress in a cgroup with chroot
    This should max out CPU usage and test the CPU limit
    
    Args:
        cgroup_name: Name of the cgroup
        cpu_limit: CPU limit as percentage (e.g., 10 for 10% of one core)
    """
    python_code = '''
import time
import threading
import os
import psutil

def cpu_stress():
    """Aggressive CPU stress with monitoring"""
    count = 0
    start_time = time.time()
    while count < 5000000:  # Increased iterations
        # More intensive CPU operations
        for i in range(10000):
            _ = i ** 3 + i ** 2 + i * 3.14159
        count += 1
        
        # Report progress every 100k iterations
        if count % 100000 == 0:
            elapsed = time.time() - start_time
            rate = count / elapsed if elapsed > 0 else 0
            print(f"Thread completed {count} iterations in {elapsed:.1f}s (rate: {rate:.0f}/s)")
        
print(f"Starting AGGRESSIVE CPU stress test with PID: {os.getpid()}")
print("This will hammer the CPU with intensive math operations...")

# Start multiple threads for maximum stress
threads = []
for i in range(8):  # Back to 8 threads for maximum stress
    t = threading.Thread(target=cpu_stress)
    t.daemon = True
    t.start()
    threads.append(t)
    print(f"Started aggressive CPU thread {i+1}")

# Monitor CPU usage while running
start_time = time.time()
try:
    for i in range(20):  # Run for 40 seconds max
        elapsed = time.time() - start_time
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            print(f"CPU stress running for {elapsed:.1f}s - CPU usage: {cpu_percent}%", flush=True)
        except:
            print(f"CPU stress running for {elapsed:.1f}s - monitoring unavailable", flush=True)
        time.sleep(1)
    print("CPU stress test completed")
except KeyboardInterrupt:
    print("Interrupted by user")
'''
    
    try:
        return run_in_cgroup_chroot(
            cgroup_name=cgroup_name,
            chroot_dir="./extracted_python",
            command=f"python3 -c '{python_code}'",
            memory_limit="500M",  # Give enough memory but limit CPU
            cpu_limit=cpu_limit
        )
    except Exception as e:
        print(f"❌ CPU stress test failed: {e}")
        return None


def test_cpu_bomb(cgroup_name="cpu_bomb", cpu_limit=5):
    """
    Test EXTREME CPU usage (CPU bomb) in a cgroup
    This creates maximum CPU stress to test the limits
    
    Args:
        cgroup_name: Name of the cgroup
        cpu_limit: CPU limit as percentage (e.g., 5 for 5% of one core)
    """
    python_code = '''
import os
import time
import threading
import multiprocessing
import math

def cpu_bomb():
    """EXTREME CPU-intensive operations"""
    count = 0
    while count < 10000000:  # Massive iteration count
        # Extremely CPU intensive operations
        for i in range(1000):
            _ = math.pow(i, 3) + math.sqrt(i + 1) + math.sin(i) + math.cos(i)
        count += 1
        
        # Report progress less frequently to avoid I/O overhead
        if count % 500000 == 0:
            print(f"💥 CPU BOMB: {count} iterations completed", flush=True)

def fork_bomb_simulation():
    """Simulate fork bomb behavior with threads"""
    threads = []
    for i in range(16):  # Create many threads
        t = threading.Thread(target=cpu_bomb)
        t.daemon = True
        t.start()
        threads.append(t)
    return threads
        
print(f"🚨 Starting EXTREME CPU BOMB test with PID: {os.getpid()}")
print("WARNING: This will attempt to completely saturate CPU!")
print("The cgroup should heavily throttle this process...")

# Get system info
num_cores = multiprocessing.cpu_count()
print(f"System has {num_cores} CPU cores")

# Start the bomb
bomb_threads = fork_bomb_simulation()
print(f"🔥 Started {len(bomb_threads)} CPU bomb threads")

# Additional stress: start processes too
processes = []
for i in range(4):  # Start some processes too
    import subprocess
    import sys
    
    bomb_code = \"\"\"
import time
count = 0
while count < 1000000:
    for i in range(10000):
        _ = i ** 4 + i ** 3 + i ** 2
    count += 1
\"\"\"
    
    try:
        p = subprocess.Popen([sys.executable, '-c', bomb_code], 
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        processes.append(p)
        print(f"💀 Started CPU bomb process {i+1} (PID: {p.pid})")
    except:
        pass

# Monitor the chaos
start_time = time.time()
try:
    for i in range(60):  # Run for up to 60 seconds
        elapsed = time.time() - start_time
        alive_processes = sum(1 for p in processes if p.poll() is None)
        print(f"🔥 CPU BOMB running for {elapsed:.1f}s - {alive_processes} processes alive", flush=True)
        time.sleep(1)
    print("CPU bomb test completed")
except KeyboardInterrupt:
    print("Interrupted - stopping bomb")
finally:
    # Clean up processes
    for p in processes:
        try:
            p.terminate()
        except:
            pass
'''
    
    try:
        return run_in_cgroup_chroot(
            cgroup_name=cgroup_name,
            chroot_dir="./extracted_python",
            command=f"python3 -c '{python_code}'",
            memory_limit="200M",  # Very limited memory and CPU
            cpu_limit=cpu_limit
        )
    except Exception as e:
        print(f"❌ CPU bomb test failed: {e}")
        return None


def test_ultimate_cpu_destroyer(cgroup_name="cpu_destroyer", cpu_limit=2):
    """
    ULTIMATE CPU stress test - this should completely max out the system
    while being constrained by cgroups
    """
    python_code = '''
import os
import time
import threading
import multiprocessing
import math
import random

def ultimate_cpu_destroyer():
    """The most CPU-intensive function possible"""
    count = 0
    while True:  # Infinite loop - let timeout handle it
        # Combine multiple CPU-intensive operations
        for i in range(50000):
            # Mathematical operations
            a = math.pow(i, 4) + math.sqrt(i + 1)
            b = math.sin(i) + math.cos(i) + math.tan(i + 1)
            c = math.log(i + 1) + math.exp(i % 10)
            
            # String operations
            s = str(a * b * c) * 100
            _ = s.upper().lower().replace('e', '3')
            
            # Random operations
            _ = random.random() * random.randint(1, 1000)
        
        count += 1
        if count % 10 == 0:
            print(f"💀 DESTROYER: {count * 50000} operations completed", flush=True)

print(f"💀💀💀 ULTIMATE CPU DESTROYER ACTIVATED 💀💀💀")
print(f"PID: {os.getpid()}")
print("This will try to completely destroy your CPU!")
print("Only cgroups can save you now...")

# Get maximum threads
max_threads = multiprocessing.cpu_count() * 4
print(f"Starting {max_threads} destroyer threads...")

# Start maximum stress
threads = []
for i in range(max_threads):
    t = threading.Thread(target=ultimate_cpu_destroyer)
    t.daemon = True
    t.start()
    threads.append(t)
    print(f"💀 Destroyer thread {i+1} activated")

# Let it run and monitor
start_time = time.time()
try:
    while True:
        elapsed = time.time() - start_time
        print(f"💀 CPU DESTROYER running for {elapsed:.1f}s - System should be at {cpu_limit}% CPU!", flush=True)
        time.sleep(2)
except KeyboardInterrupt:
    print("Interrupted - destroyer stopped")
'''
    
    try:
        return run_in_cgroup_chroot(
            cgroup_name=cgroup_name,
            chroot_dir="./extracted_python",
            command=f"python3 -c '{python_code}'",
            memory_limit="100M",  # Minimal memory, minimal CPU
            cpu_limit=cpu_limit
        )
    except Exception as e:
        print(f"❌ CPU destroyer test failed: {e}")
        return None


def run_all_tests():
    """Run all tests with proper error handling"""
    tests = [
        ("Basic chroot test", lambda: test_chroot_python()),
        ("CPU stress test (10% limit)", lambda: test_cpu_stress(cgroup_name="cpu_demo", cpu_limit=10)),
        ("CPU bomb test (5% limit)", lambda: test_cpu_bomb(cgroup_name="cpu_bomb", cpu_limit=5)),
        ("ULTIMATE CPU destroyer (2% limit)", lambda: test_ultimate_cpu_destroyer(cgroup_name="cpu_destroyer", cpu_limit=2)),
    ]
    
    for test_name, test_func in tests:
        print(f"\n{'='*60}")
        print(f"🧪 Running: {test_name}")
        print('='*60)
        
        try:
            result = test_func()
            if result is not None:
                print(f"✅ {test_name} completed")
            else:
                print(f"⚠️  {test_name} completed with warnings")
        except Exception as e:
            print(f"❌ {test_name} failed: {e}")
            print("Continuing with next test...")
        
        print(f"{'='*60}")


# %% Test basic chroot functionality
print("Testing chroot Python version:")
test_chroot_python()

# %% Run all tests safely
print("\n🚀 Starting comprehensive container tests...")
run_all_tests()
print("\n✅ All tests completed!")
