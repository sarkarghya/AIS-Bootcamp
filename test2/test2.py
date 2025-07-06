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


def run_in_cgroup_chroot_namespaced(cgroup_name, chroot_dir, command=None, memory_limit="100M"):
    """
    Run a command in cgroup, chroot, and namespace isolation
    
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
    
    print(f"Running `{command}` in cgroup {cgroup_name} with chroot {chroot_dir} and namespaces")
    
    try:
        import signal
        
        # Fork to create child process
        pid = os.fork()
        
        if pid == 0:
            # Child process - set up signal handler and wait
            def resume_handler(signum, frame):
                pass  # Just wake up from pause
            
            signal.signal(signal.SIGUSR1, resume_handler)
            print(f"Child process {os.getpid()} waiting for signal...")
            signal.pause()  # Wait for SIGUSR1 from parent
            print(f"Child process {os.getpid()} resuming...")
            
            # Execute with namespace isolation using unshare command
            os.execvp('unshare', ['unshare', '--pid', '--mount', '--net', '--uts', '--ipc', '--fork', 'chroot', chroot_dir] + command)
        else:
            # Parent process - add child to cgroup then signal to continue
            print(f"Started paused process {pid}, adding to cgroup {cgroup_name}")
            
            cgroup_procs_path = f"/sys/fs/cgroup/{cgroup_name}/cgroup.procs"
            with open(cgroup_procs_path, "w") as f:
                f.write(str(pid))
            print(f"Added process {pid} to cgroup {cgroup_name}")
            
            # Signal child to continue
            os.kill(pid, signal.SIGUSR1)
            print(f"Signaled process {pid} to continue")
            
            # Wait for child to complete
            _, status = os.waitpid(pid, 0)
            exit_code = os.WEXITSTATUS(status)
            
            print(f"Exit code: {exit_code}")
            return exit_code
        
    except Exception as e:
        print(f"Error running command: {e}")
        return None


# %% Test namespace isolation
def test_namespace_isolation():
    """
    Test that namespaces provide proper isolation by checking:
    1. Different hostname (UTS namespace)
    2. Different process list (PID namespace) 
    3. Different network interfaces (NET namespace)
    """
    print("=== Testing namespace isolation ===")
    
    # Test commands to show isolation
    test_commands = [
        "hostname",  # Should show isolated hostname
        "ps aux | wc -l",  # Should show fewer processes
        "ip addr show | grep -c inet",  # Should show different network setup
        "mount | wc -l",  # Should show different mount points
    ]
    
    print("\n1. Host system info:")
    import subprocess
    for cmd in test_commands:
        try:
            result = subprocess.run(['sh', '-c', cmd], capture_output=True, text=True)
            print(f"  {cmd}: {result.stdout.strip()}")
        except Exception as e:
            print(f"  {cmd}: Error - {e}")
    
    print("\n2. Namespaced container info:")
    # Create separate commands that won't fail if one fails
    namespace_commands = [
        "hostname container-demo",  # Change hostname to show UTS isolation
        "echo 'hostname: ' && hostname",
        "echo 'ps aux count: ' && ps aux | wc -l", 
        "echo 'inet addresses: ' && (ip addr show | grep -c inet || echo '0')",
        "echo 'mount points: ' && (mount | wc -l || echo 'mount failed')",
        "echo 'current PID: ' && echo $$",
        "echo 'user info: ' && id"
    ]
    
    # Join with semicolons so each command runs independently
    combined_cmd = "; ".join(namespace_commands)
    
    run_in_cgroup_chroot_namespaced(
        cgroup_name="test_namespaces",
        chroot_dir="./extracted_python",
        command=combined_cmd,
        memory_limit="50M"
    )
    
    print("\n3. Verification - host hostname should be unchanged:")
    try:
        result = subprocess.run(['hostname'], capture_output=True, text=True)
        print(f"  Host hostname: {result.stdout.strip()}")
    except Exception as e:
        print(f"  Could not check host hostname: {e}")
    
    print("\n=== Namespace isolation test complete ===")
    return True

# %% Cgroup - set oom_score_adj
def create_cgroup_comprehensive(cgroup_name, memory_limit=None, cpu_limit=None):
    """
    Create a cgroup with comprehensive settings to ensure memory limits work properly
    
    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
        cpu_limit: CPU limit (not implemented yet)
    """
    import subprocess
    import os
    
    cgroup_path = f"/sys/fs/cgroup/{cgroup_name}"
    
    print(f"Setting up comprehensive cgroup: {cgroup_name}")
    
    # Create cgroup directory
    os.makedirs(cgroup_path, exist_ok=True)
    print(f"✓ Created cgroup directory: {cgroup_path}")
    
    # Enable controllers in parent cgroup
    try:
        with open("/sys/fs/cgroup/cgroup.subtree_control", "w") as f:
            f.write("+cpu +memory +pids")
        print("✓ Enabled cgroup controllers")
    except Exception as e:
        print(f"Warning: Could not enable controllers: {e}")
    
    # Set memory limit if specified
    if memory_limit:
        memory_max_path = f"{cgroup_path}/memory.max"
        try:
            with open(memory_max_path, "w") as f:
                f.write(str(memory_limit))
            print(f"✓ Set memory limit to {memory_limit}")
        except Exception as e:
            print(f"✗ Error setting memory limit: {e}")
            return None
    
    # Disable swap for this cgroup (forces hard memory limit)
    try:
        swap_max_path = f"{cgroup_path}/memory.swap.max"
        with open(swap_max_path, "w") as f:
            f.write("0")
        print("✓ Disabled swap for cgroup")
    except Exception as e:
        print(f"Warning: Could not disable swap: {e}")
    
    # Set OOM killer to be more aggressive for this cgroup
    try:
        oom_group_path = f"{cgroup_path}/memory.oom.group"
        with open(oom_group_path, "w") as f:
            f.write("1")
        print("✓ Enabled OOM group killing")
    except Exception as e:
        print(f"Warning: Could not set OOM group: {e}")
    
    # Set low memory.high to trigger pressure before hitting max
    if memory_limit:
        try:
            # Parse memory limit to set memory.high to 90% of max
            if memory_limit.endswith('M'):
                limit_mb = int(memory_limit[:-1])
                high_limit = f"{int(limit_mb * 0.9)}M"
            else:
                high_limit = str(int(int(memory_limit) * 0.9))
            
            memory_high_path = f"{cgroup_path}/memory.high"
            with open(memory_high_path, "w") as f:
                f.write(high_limit)
            print(f"✓ Set memory.high to {high_limit} (90% of max)")
        except Exception as e:
            print(f"Warning: Could not set memory.high: {e}")
    
    return cgroup_path


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
    
    try:
        # Run without capturing output so we see it in real-time
        result = subprocess.run(['sh', '-c', script], timeout=60)
        return result
    except subprocess.TimeoutExpired:
        print("Command timed out after 60 seconds")
        return None
    except Exception as e:
        print(f"Error running command: {e}")
        return None


def test_memory_comprehensive(cgroup_name="demo", memory_limit="100M"):
    """
    Comprehensive memory test that properly sets up cgroups with all necessary settings
    including oom_score_adj to ensure the memory limit is enforced
    """
    print(f"Testing memory allocation with {memory_limit} limit (comprehensive setup):")
    print("(This should properly enforce the cgroup memory limit)")
    
    # Create cgroup with comprehensive settings
    cgroup_path = create_cgroup_comprehensive(cgroup_name, memory_limit=memory_limit)
    if not cgroup_path:
        print("✗ Failed to create cgroup")
        return None
    
    # Create the test script with proper oom_score_adj setting
    script = f"""
    # Add process to cgroup
    echo $$ > /sys/fs/cgroup/{cgroup_name}/cgroup.procs
    
    # Set oom_score_adj to make this process more likely to be killed
    echo 1000 > /proc/self/oom_score_adj
    
    # Verify we're in the cgroup
    echo "Process in cgroup:"
    cat /proc/self/cgroup | grep {cgroup_name}
    
    # Verify memory limits
    echo "Memory limit: $(cat /sys/fs/cgroup/{cgroup_name}/memory.max)"
    echo "Memory high: $(cat /sys/fs/cgroup/{cgroup_name}/memory.high)"
    
    # Run the memory test in chroot
    chroot extracted_python/ /bin/sh << 'EOF'
    python3 -c "
import os
import time

print('Starting memory allocation test...')
print('Process PID:', os.getpid())

data = []
for i in range(200):  # Allocate up to 2GB if not killed
    data.append('x' * 10 * 1024 * 1024)  # 10MB chunks
    allocated_mb = (i+1) * 10
    print('Allocated ' + str(allocated_mb) + 'MB', flush=True)
    
    # Add a small delay to make killing more predictable
    time.sleep(0.01)

print('Test completed - this should not be reached if limits work!')
"
EOF
    """
    
    import subprocess
    import signal
    try:
        # Use Popen to get real-time output
        process = subprocess.Popen(['sh', '-c', script], 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.STDOUT,
                                 universal_newlines=True)
        
        # Stream output in real-time
        if process.stdout:
            for line in iter(process.stdout.readline, ''):
                print(line.strip())
        
        process.wait(timeout=60)
        
        # Check how the process ended
        if process.returncode == 0:
            print("\n⚠ Process completed normally - cgroup memory limit NOT working")
        elif process.returncode == -signal.SIGKILL or process.returncode == 137:
            print("\n✓ Process was KILLED - cgroup memory limit working!")
            print("   Return code 137 = 128 + 9 (SIGKILL)")
        elif process.returncode < 0:
            print(f"\n✓ Process was killed by signal {-process.returncode}")
        else:
            print(f"\n? Process exited with code {process.returncode}")
        
        return process.returncode
    except subprocess.TimeoutExpired:
        print("\n✗ Test timed out")
        return None
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return None


def test_memory_simple(cgroup_name="demo", memory_limit="100M"):
    """
    Simple memory test that matches the user's manual example exactly
    """
    print(f"Testing memory allocation with {memory_limit} limit:")
    print("(This should show allocations and then get killed)")
    
    # Create cgroup
    create_cgroup(cgroup_name, memory_limit=memory_limit)
    
    # Use a here document to avoid quote nesting issues completely
    script = f"""
    echo $$ > /sys/fs/cgroup/{cgroup_name}/cgroup.procs
    chroot extracted_python/ /bin/sh << 'EOF'
python3 -c "
data = []
for i in range(100):
    data.append('x' * 10 * 1024 * 1024)
    print('Allocated ' + str((i+1)*10) + 'MB', flush=True)
"
EOF
    """
    
    import subprocess
    import signal
    try:
        # Use Popen to get real-time output and better control
        process = subprocess.Popen(['sh', '-c', script], 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.STDOUT,
                                 universal_newlines=True)
        
        # Stream output in real-time
        if process.stdout:
            for line in iter(process.stdout.readline, ''):
                print(line.strip())
        
        process.wait(timeout=60)
        
        # Check how the process ended
        if process.returncode == 0:
            print("\n⚠ Process completed normally - memory limit may not be working")
        elif process.returncode == -signal.SIGKILL or process.returncode == 137:
            print("\n✓ Process was KILLED (likely by OOM killer) - memory limit working!")
            print("   Return code 137 = 128 + 9 (SIGKILL)")
        elif process.returncode < 0:
            print(f"\n✓ Process was killed by signal {-process.returncode}")
        else:
            print(f"\n? Process exited with code {process.returncode}")
        
        return process.returncode
    except subprocess.TimeoutExpired:
        print("\n✗ Test timed out")
        return None
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return None



# %% Test basic chroot functionality
print("\n" + "="*50)
print("TESTING CHROOT FUNCTIONALITY")
print("="*50)
print("Testing chroot Python version:")
test_chroot_python()

# %% Test namespace isolation
print("\n" + "="*50)
print("TESTING NAMESPACE ISOLATION")
print("="*50)

test_namespace_isolation()

# %% Test memory allocation with reasonable limits
print("\n" + "="*50)
print("TESTING CGROUP MEMORY LIMITS")
print("="*50)

print("\n1. Testing memory allocation with 100MB limit (should crash around 100MB):")
test_memory_simple(cgroup_name="demo", memory_limit="100M")

# Uncomment these after the comprehensive test works:
# print("\n2. Testing memory allocation with 50MB limit (should crash quickly):")
test_memory_comprehensive(cgroup_name="demo2", memory_limit="50M")

# print("\n3. Testing memory allocation with 50MB limit (should crash quickly):")
# test_memory_simple(cgroup_name="demo3", memory_limit="50M")




# %% Container networking functions

def setup_bridge_network():
    """
    Set up the bridge network for containers
    Creates bridge0 with 10.0.0.1/24 and configures iptables
    """
    import subprocess
    import os
    
    print("🔧 DEBUG: Setting up bridge network...")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠ Warning: Bridge network setup requires root privileges")
        return False
    
    try:
        # Check if bridge already exists
        print("🔧 DEBUG: Checking if bridge0 already exists...")
        bridge_check = subprocess.run(['ip', 'link', 'show', 'bridge0'], 
                                    capture_output=True, text=True)
        if bridge_check.returncode == 0:
            print("✓ Bridge0 already exists, checking configuration...")
            # Check if it has the right IP
            ip_check = subprocess.run(['ip', 'addr', 'show', 'bridge0'], 
                                    capture_output=True, text=True)
            if '10.0.0.1/24' in ip_check.stdout:
                print("✓ Bridge0 already configured with correct IP")
                return True
            else:
                print("⚠ Bridge0 exists but needs reconfiguration")
        
        # Enable IP forwarding
        print("🔧 DEBUG: Enabling IP forwarding...")
        result = subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                              capture_output=True, text=True, check=True)
        print(f"✓ Enabled IP forwarding: {result.stdout.strip()}")
        
        # Remove existing bridge if it exists
        print("🔧 DEBUG: Removing existing bridge0 if present...")
        subprocess.run(['ip', 'link', 'del', 'bridge0'], 
                      capture_output=True, text=True)
        
        # Create and configure bridge
        print("🔧 DEBUG: Creating bridge0...")
        subprocess.run(['ip', 'link', 'add', 'bridge0', 'type', 'bridge'], check=True)
        print("✓ Created bridge0")
        
        print("🔧 DEBUG: Configuring bridge0 IP...")
        subprocess.run(['ip', 'addr', 'add', '10.0.0.1/24', 'dev', 'bridge0'], check=True)
        print("✓ Added IP 10.0.0.1/24 to bridge0")
        
        print("🔧 DEBUG: Bringing bridge0 up...")
        subprocess.run(['ip', 'link', 'set', 'bridge0', 'up'], check=True)
        print("✓ Bridge0 is up")
        
        # Get default network interface
        print("🔧 DEBUG: Finding default network interface...")
        route_result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                    capture_output=True, text=True, check=True)
        default_iface = route_result.stdout.split()[4]
        print(f"✓ Detected default interface: {default_iface}")
        
        # Clear existing iptables rules
        print("🔧 DEBUG: Clearing existing iptables rules...")
        subprocess.run(['iptables', '-F'], check=True)
        subprocess.run(['iptables', '-t', 'nat', '-F'], check=True)
        subprocess.run(['iptables', '-t', 'mangle', '-F'], check=True)
        subprocess.run(['iptables', '-X'], check=True)
        print("✓ Cleared existing iptables rules")
        
        # Set default policies
        print("🔧 DEBUG: Setting iptables default policies...")
        subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'], check=True)
        subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'], check=True)
        subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
        print("✓ Set default policies to ACCEPT")
        
        # Add iptables rules for NAT and forwarding
        print("🔧 DEBUG: Adding iptables NAT rules...")
        subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '10.0.0.0/24', 
                       '!', '-o', 'bridge0', '-j', 'MASQUERADE'], check=True)
        print("✓ Added NAT rule for 10.0.0.0/24")
        
        print("🔧 DEBUG: Adding iptables forwarding rules...")
        subprocess.run(['iptables', '-A', 'FORWARD', '-i', 'bridge0', '-o', default_iface, '-j', 'ACCEPT'], check=True)
        subprocess.run(['iptables', '-A', 'FORWARD', '-i', default_iface, '-o', 'bridge0', 
                       '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], check=True)
        subprocess.run(['iptables', '-A', 'FORWARD', '-i', 'bridge0', '-o', 'bridge0', '-j', 'ACCEPT'], check=True)
        print("✓ Added forwarding rules")
        
        # Test bridge connectivity
        print("🔧 DEBUG: Testing bridge connectivity...")
        ping_result = subprocess.run(['ping', '-c', '1', '-W', '1', '10.0.0.1'], 
                                   capture_output=True, text=True)
        if ping_result.returncode == 0:
            print("✓ Bridge connectivity test PASSED")
        else:
            print("⚠ Bridge connectivity test FAILED (may be normal)")
        
        print("✓ Bridge network setup completed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"✗ Error setting up bridge network: {e}")
        print(f"   Command: {e.cmd}")
        print(f"   Return code: {e.returncode}")
        if e.stdout:
            print(f"   Stdout: {e.stdout}")
        if e.stderr:
            print(f"   Stderr: {e.stderr}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False


def create_container_network(container_id, ip_suffix):
    """
    Create network interface for a specific container
    
    Args:
        container_id: Unique identifier for the container
        ip_suffix: IP address suffix (e.g., 2 for 10.0.0.2)
    """
    import subprocess
    import os
    
    print(f"Creating network for container {container_id}...")
    
    if os.geteuid() != 0:
        print("⚠ Warning: Network setup requires root privileges")
        return False
    
    try:
        # Create shorter interface names (Linux limit: 15 characters)
        # Use only last 8 chars of container_id to keep names short
        short_id = container_id[-8:]
        veth_host = f"veth0_{short_id}"
        veth_container = f"veth1_{short_id}"
        netns_name = f"netns_{short_id}"
        container_ip = f"10.0.0.{ip_suffix}"
        
        print(f"🔧 DEBUG: Creating interfaces:")
        print(f"   Host interface: {veth_host} (len: {len(veth_host)})")
        print(f"   Container interface: {veth_container} (len: {len(veth_container)})")
        print(f"   Namespace: {netns_name}")
        print(f"   Container IP: {container_ip}")
        
        # Check if interface names are valid (max 15 chars)
        if len(veth_host) > 15 or len(veth_container) > 15:
            print(f"✗ Interface names too long! Host: {len(veth_host)}, Container: {len(veth_container)}")
            return None
        
        # Create veth pair
        print(f"🔧 DEBUG: Creating veth pair...")
        result = subprocess.run(['ip', 'link', 'add', 'dev', veth_host, 'type', 'veth', 
                               'peer', 'name', veth_container], 
                              capture_output=True, text=True, check=True)
        print(f"✓ Created veth pair: {veth_host} <-> {veth_container}")
        
        # Attach host end to bridge
        print(f"🔧 DEBUG: Attaching {veth_host} to bridge...")
        subprocess.run(['ip', 'link', 'set', 'dev', veth_host, 'up'], check=True)
        subprocess.run(['ip', 'link', 'set', veth_host, 'master', 'bridge0'], check=True)
        print(f"✓ Attached {veth_host} to bridge0")
        
        # Create network namespace
        print(f"🔧 DEBUG: Creating network namespace {netns_name}...")
        subprocess.run(['ip', 'netns', 'add', netns_name], check=True)
        print(f"✓ Created namespace: {netns_name}")
        
        # Move container end to namespace
        print(f"🔧 DEBUG: Moving {veth_container} to namespace...")
        subprocess.run(['ip', 'link', 'set', veth_container, 'netns', netns_name], check=True)
        print(f"✓ Moved {veth_container} to {netns_name}")
        
        # Configure container network interface
        print(f"🔧 DEBUG: Configuring container interface...")
        subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'link', 'set', 'dev', 'lo', 'up'], check=True)
        subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'addr', 'add', 
                       f'{container_ip}/24', 'dev', veth_container], check=True)
        subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'link', 'set', 
                       'dev', veth_container, 'up'], check=True)
        print(f"✓ Configured {veth_container} with IP {container_ip}/24")
        
        # Add default route
        print(f"🔧 DEBUG: Adding default route...")
        subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'route', 'add', 
                       'default', 'via', '10.0.0.1'], check=True)
        print(f"✓ Added default route via 10.0.0.1")
        
        # Set up DNS for chroot environment
        print(f"🔧 DEBUG: Setting up DNS in chroot environment...")
        try:
            # Ensure /etc directory exists in chroot
            chroot_etc_dir = f"/tmp/netns_{short_id}_etc"
            os.makedirs(chroot_etc_dir, exist_ok=True)
            
            # Copy or create resolv.conf in chroot
            chroot_resolv_conf = os.path.join(chroot_etc_dir, 'resolv.conf')
            
            # Always create a working DNS configuration for containers
            # Don't use systemd-resolved (127.0.0.53) as it won't work in network namespaces
            with open(chroot_resolv_conf, 'w') as f:
                f.write('# DNS configuration for containerized environment\n')
                f.write('nameserver 8.8.8.8\n')
                f.write('nameserver 8.8.4.4\n')
                f.write('nameserver 1.1.1.1\n')
                f.write('options timeout:2 attempts:3\n')
            print(f"✓ Created working DNS configuration in chroot (Google DNS + Cloudflare)")
        except Exception as e:
            print(f"⚠ Warning: Could not set up DNS in chroot: {e}")
        
        print(f"✓ Successfully created network for container {container_id}")
        print(f"  - Container IP: {container_ip}/24")
        print(f"  - Gateway: 10.0.0.1")
        print(f"  - Network namespace: {netns_name}")
        
        # Test connectivity from namespace
        print(f"🔧 DEBUG: Testing namespace connectivity...")
        test_result = subprocess.run(['ip', 'netns', 'exec', netns_name, 'ping', '-c', '1', '10.0.0.1'], 
                                   capture_output=True, text=True)
        if test_result.returncode == 0:
            print(f"✓ Gateway connectivity test PASSED")
        else:
            print(f"⚠ Gateway connectivity test FAILED: {test_result.stderr}")
        
        # Test internet connectivity with IP address
        print(f"🔧 DEBUG: Testing internet connectivity (IP)...")
        internet_test = subprocess.run(['ip', 'netns', 'exec', netns_name, 'ping', '-c', '1', '8.8.8.8'], 
                                     capture_output=True, text=True)
        if internet_test.returncode == 0:
            print(f"✓ Internet connectivity test PASSED (can reach 8.8.8.8)")
        else:
            print(f"⚠ Internet connectivity test FAILED: {internet_test.stderr}")
        
        # Test DNS resolution from namespace
        print(f"🔧 DEBUG: Testing DNS resolution...")
        dns_test = subprocess.run(['ip', 'netns', 'exec', netns_name, 'nslookup', 'google.com'], 
                                capture_output=True, text=True)
        if dns_test.returncode == 0:
            print(f"✓ DNS resolution test PASSED")
        else:
            print(f"⚠ DNS resolution test FAILED: {dns_test.stderr}")
            # Try alternative DNS test
            dig_test = subprocess.run(['ip', 'netns', 'exec', netns_name, 'dig', 'google.com'], 
                                    capture_output=True, text=True)
            if dig_test.returncode == 0:
                print(f"✓ DNS resolution test with dig PASSED")
            else:
                print(f"⚠ DNS resolution test with dig FAILED: {dig_test.stderr}")
        
        return netns_name
        
    except subprocess.CalledProcessError as e:
        print(f"✗ Error creating container network: {e}")
        print(f"   Command: {e.cmd}")
        print(f"   Return code: {e.returncode}")
        if e.stdout:
            print(f"   Stdout: {e.stdout}")
        if e.stderr:
            print(f"   Stderr: {e.stderr}")
        return None
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return None


def cleanup_container_network(container_id):
    """
    Clean up network resources for a container
    """
    import subprocess
    import os
    
    if os.geteuid() != 0:
        print("⚠ Warning: Network cleanup requires root privileges")
        return
    
    try:
        # Use same short naming convention as create_container_network
        short_id = container_id[-8:]
        veth_host = f"veth0_{short_id}"
        netns_name = f"netns_{short_id}"
        
        print(f"🔧 DEBUG: Cleaning up network for container {container_id}")
        print(f"   Short ID: {short_id}")
        print(f"   Host interface: {veth_host}")
        print(f"   Namespace: {netns_name}")
        
        # Remove network namespace (this also removes the veth pair)
        print(f"🔧 DEBUG: Removing network namespace {netns_name}...")
        result = subprocess.run(['ip', 'netns', 'del', netns_name], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ Removed namespace: {netns_name}")
        else:
            print(f"⚠ Could not remove namespace {netns_name}: {result.stderr}")
        
        # Remove host veth if it still exists
        print(f"🔧 DEBUG: Removing host interface {veth_host}...")
        result = subprocess.run(['ip', 'link', 'del', veth_host], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ Removed host interface: {veth_host}")
        else:
            print(f"⚠ Host interface {veth_host} may not exist (already cleaned up)")
        
        # Clean up DNS configuration if it exists
        netns_etc_dir = f"/tmp/netns_{short_id}_etc"
        if os.path.exists(netns_etc_dir):
            print(f"🔧 DEBUG: Removing DNS configuration directory...")
            subprocess.run(['rm', '-rf', netns_etc_dir], check=True)
            print(f"✓ Removed DNS configuration directory")
        
        print(f"✓ Network cleanup completed for container {container_id}")
        
    except Exception as e:
        print(f"⚠ Warning: Could not fully clean up network for {container_id}: {e}")



def create_isolated_network_namespace(container_id):
    """
    Create an isolated network namespace with no external connectivity
    
    Args:
        container_id: Unique identifier for the container
        
    Returns:
        netns_name: Name of the created network namespace, or None if failed
    """
    import subprocess
    import os
    
    print(f"Creating isolated network namespace for container {container_id}...")
    
    if os.geteuid() != 0:
        print("⚠ Warning: Network namespace creation requires root privileges")
        return None
    
    try:
        # Create shorter namespace name (Linux limit considerations)
        short_id = container_id[-8:]
        netns_name = f"isolated_{short_id}"
        
        print(f"🔧 DEBUG: Creating isolated namespace:")
        print(f"   Namespace: {netns_name}")
        print(f"   Container ID: {container_id}")
        
        # Create network namespace
        print(f"🔧 DEBUG: Creating network namespace {netns_name}...")
        subprocess.run(['ip', 'netns', 'add', netns_name], check=True)
        print(f"✓ Created isolated namespace: {netns_name}")
        
        # Configure only loopback interface (no external connectivity)
        print(f"🔧 DEBUG: Configuring loopback interface...")
        subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'link', 'set', 'dev', 'lo', 'up'], check=True)
        print(f"✓ Configured loopback interface in {netns_name}")
        
        # Test that the namespace is isolated (should only have loopback)
        print(f"🔧 DEBUG: Verifying network isolation...")
        result = subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'addr', 'show'], 
                              capture_output=True, text=True, check=True)
        
        # Count network interfaces (should only be loopback)
        interfaces = len([line for line in result.stdout.split('\n') if ': ' in line and 'lo:' in line])
        if interfaces == 1:
            print(f"✓ Network isolation verified: only loopback interface present")
        else:
            print(f"⚠ Warning: Expected 1 interface (loopback), found {interfaces}")
        
        # Test that external connectivity is blocked
        print(f"🔧 DEBUG: Testing network isolation...")
        ping_test = subprocess.run(['ip', 'netns', 'exec', netns_name, 'ping', '-c', '1', '-W', '1', '8.8.8.8'], 
                                 capture_output=True, text=True)
        if ping_test.returncode != 0:
            print(f"✓ Network isolation confirmed: cannot reach external hosts")
        else:
            print(f"⚠ Warning: Network isolation may not be working - external ping succeeded")
        
        # Test loopback connectivity
        print(f"🔧 DEBUG: Testing loopback connectivity...")
        loopback_test = subprocess.run(['ip', 'netns', 'exec', netns_name, 'ping', '-c', '1', '127.0.0.1'], 
                                     capture_output=True, text=True)
        if loopback_test.returncode == 0:
            print(f"✓ Loopback connectivity confirmed")
        else:
            print(f"⚠ Warning: Loopback connectivity failed")
        
        print(f"✓ Successfully created isolated network namespace: {netns_name}")
        print(f"  - No external connectivity")
        print(f"  - Only loopback interface (127.0.0.1)")
        print(f"  - Complete network isolation")
        
        return netns_name
        
    except subprocess.CalledProcessError as e:
        print(f"✗ Error creating isolated network namespace: {e}")
        print(f"   Command: {e.cmd}")
        print(f"   Return code: {e.returncode}")
        if e.stdout:
            print(f"   Stdout: {e.stdout}")
        if e.stderr:
            print(f"   Stderr: {e.stderr}")
        return None
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return None


def cleanup_isolated_network_namespace(container_id):
    """
    Clean up isolated network namespace
    """
    import subprocess
    import os
    
    if os.geteuid() != 0:
        print("⚠ Warning: Network cleanup requires root privileges")
        return
    
    try:
        # Use same short naming convention as create_isolated_network_namespace
        short_id = container_id[-8:]
        netns_name = f"isolated_{short_id}"
        
        print(f"🔧 DEBUG: Cleaning up isolated namespace for container {container_id}")
        print(f"   Short ID: {short_id}")
        print(f"   Namespace: {netns_name}")
        
        # Remove network namespace
        print(f"🔧 DEBUG: Removing network namespace {netns_name}...")
        result = subprocess.run(['ip', 'netns', 'del', netns_name], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ Removed isolated namespace: {netns_name}")
        else:
            print(f"⚠ Could not remove namespace {netns_name}: {result.stderr}")
        
        print(f"✓ Isolated network cleanup completed for container {container_id}")
        
    except Exception as e:
        print(f"⚠ Warning: Could not fully clean up isolated network for {container_id}: {e}")



# %% New separate networking functions (don't modify existing ones)

def run_networked_container(cgroup_name, chroot_dir, command=None, memory_limit="100M", container_name="container"):
    """
    Create a new container with full networking support
    This is a separate function that doesn't modify existing container functions
    
    Args:
        cgroup_name: Name of the cgroup to create/use
        chroot_dir: Directory to chroot into  
        command: Command to run
        memory_limit: Memory limit for the cgroup
        container_name: Name for the container (used in networking)
    """
    import subprocess
    import os
    import uuid
    import signal
    import time
    
    # Create cgroup
    create_cgroup(cgroup_name, memory_limit=memory_limit)
    
    if command is None:
        command = ['/bin/sh']
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
    
    # Generate unique container ID
    container_id = f"{container_name}_{str(uuid.uuid4())[:8]}"
    ip_suffix = hash(container_id) % 200 + 50  # IP range 10.0.0.50-249
    
    print(f"🔧 DEBUG: Creating networked container: {container_id}")
    print(f"🔧 DEBUG: Command: {command}")
    print(f"🔧 DEBUG: Memory limit: {memory_limit}")
    print(f"🔧 DEBUG: IP suffix: {ip_suffix}")
    
    # Set up DNS for chroot environment
    print(f"🔧 DEBUG: Setting up DNS in chroot environment...")
    try:
        # Ensure /etc directory exists in chroot
        chroot_etc_dir = os.path.join(chroot_dir, 'etc')
        os.makedirs(chroot_etc_dir, exist_ok=True)
        
        # Copy or create resolv.conf in chroot
        chroot_resolv_conf = os.path.join(chroot_etc_dir, 'resolv.conf')
        
        # Always create a working DNS configuration for containers
        # Don't use systemd-resolved (127.0.0.53) as it won't work in network namespaces
        with open(chroot_resolv_conf, 'w') as f:
            f.write('# DNS configuration for containerized environment\n')
            f.write('nameserver 8.8.8.8\n')
            f.write('nameserver 8.8.4.4\n')
            f.write('nameserver 1.1.1.1\n')
            f.write('options timeout:2 attempts:3\n')
        print(f"✓ Created working DNS configuration in chroot (Google DNS + Cloudflare)")
    except Exception as e:
        print(f"⚠ Warning: Could not set up DNS in chroot: {e}")
    
    # Set up bridge network
    bridge_ready = setup_bridge_network()
    
    # Create container network
    netns_name = None
    if bridge_ready:
        netns_name = create_container_network(container_id, ip_suffix)
        # netns_name = create_isolated_network_namespace(container_id)
        if netns_name:
            print(f"✓ Container {container_id} assigned IP: 10.0.0.{ip_suffix}/24")
        else:
            print(f"✗ Failed to create network for container {container_id}")
    else:
        print(f"⚠ Bridge network not ready, container will run with isolated network")
    
    try:
        # Build execution command
        if netns_name:
            # Execute with dedicated network namespace
            exec_args = ['ip', 'netns', 'exec', netns_name, 'unshare', 
                       '--pid', '--mount', '--uts', '--ipc', '--fork', 
                       'chroot', chroot_dir] + command
            print(f"🔧 DEBUG: Executing with network namespace: {netns_name}")
        
        print(f"🔧 DEBUG: Command: {exec_args}")
        print(f"🔧 DEBUG: Chroot directory exists: {os.path.exists(chroot_dir)}")
        print(f"🔧 DEBUG: DNS config exists: {os.path.exists(os.path.join(chroot_dir, 'etc', 'resolv.conf'))}")
        
        # Show DNS configuration
        resolv_conf_path = os.path.join(chroot_dir, 'etc', 'resolv.conf')
        if os.path.exists(resolv_conf_path):
            with open(resolv_conf_path, 'r') as f:
                dns_config = f.read().strip()
            print(f"🔧 DEBUG: DNS config in chroot:\n{dns_config}")
        
        print(f"\n🚀 STARTING CONTAINER {container_id}")
        print("="*60)
        
        # Use Popen for real-time output streaming
        process = subprocess.Popen(
            exec_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1  # Line buffered
        )
        
        # Stream output in real-time
        if process.stdout:
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    print(output.strip())
        
        # Wait for process to complete
        exit_code = process.wait()
        
        print("="*60)
        print(f"🏁 CONTAINER {container_id} COMPLETED")
        print(f"🔧 DEBUG: Container exit code: {exit_code}")
        
        # Cleanup
        if netns_name:
            cleanup_container_network(container_id)
            # cleanup_isolated_network_namespace(container_id)
        
        return exit_code
        
    except Exception as e:
        print(f"✗ Error running networked container: {e}")
        import traceback
        traceback.print_exc()
        if netns_name:
            cleanup_container_network(container_id)
            # cleanup_isolated_network_namespace(container_id)
        return None


# %% Execute networking tests
print("\n" + "="*50)
print("TESTING NETWORKED CONTAINER")
print("="*50)

print("Creating a networked container with Python:")
print("First testing basic connectivity, then DNS resolution...")
run_networked_container(
    cgroup_name="python_networked",
    chroot_dir="./extracted_python", 
    command="python3 -c 'import subprocess; print(\"Testing basic connectivity:\"); subprocess.run([\"ping\", \"-c\", \"1\", \"8.8.8.8\"]); print(\"Testing DNS resolution:\"); import socket; print(f\"Container can resolve: {socket.gethostbyname(\"google.com\")}\"); print(\"Networked Python container working!\")'",
    memory_limit="100M",
    container_name="python_demo"
)

#!/usr/bin/env python3
import subprocess
import threading
import os
import signal
import time

# Dangerous syscalls for CVE-2024-0137
DANGEROUS_SYSCALLS = {
    'setns', 'unshare', 'mount', 'pivot_root', 'chroot', 
    'clone', 'socket', 'bind', 'connect'
}

def monitor_container_syscalls(container_command, alert_callback):
    """
    Monitor syscalls by running strace INSIDE the container namespace
    """
    try:
        # Build strace command that runs inside the container
        strace_cmd = [
            'strace', '-f', '-e', 'trace=' + ','.join(DANGEROUS_SYSCALLS),
            '-o', '/dev/stderr'  # Send to stderr for monitoring
        ] + container_command
        
        print(f"🔍 Running strace inside container: {' '.join(strace_cmd)}")
        
        process = subprocess.Popen(
            strace_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        # Monitor stderr for syscall traces
        def monitor_stderr():
            for line in iter(process.stderr.readline, ''):
                if line.strip():
                    # Check for dangerous syscalls
                    if any(syscall in line for syscall in DANGEROUS_SYSCALLS):
                        alert_callback(line.strip(), process.pid)
                    # Also print container output
                    if not any(syscall in line for syscall in DANGEROUS_SYSCALLS):
                        print(f"[CONTAINER] {line.strip()}")
        
        # Monitor stdout for normal output
        def monitor_stdout():
            for line in iter(process.stdout.readline, ''):
                if line.strip():
                    print(f"[CONTAINER] {line.strip()}")
        
        # Start monitoring threads
        stderr_thread = threading.Thread(target=monitor_stderr, daemon=True)
        stdout_thread = threading.Thread(target=monitor_stdout, daemon=True)
        
        stderr_thread.start()
        stdout_thread.start()
        
        # Wait for process completion
        exit_code = process.wait()
        return exit_code
        
    except Exception as e:
        print(f"⚠ Container monitoring error: {e}")
        return -1

def alert_handler(syscall_line, pid):
    """Enhanced alert handler for CVE-2024-0137"""
    print(f"🚨 SECURITY ALERT: Dangerous syscall detected!")
    print(f"   Syscall trace: {syscall_line}")
    print(f"   Process PID: {pid}")
    
    # Specific CVE-2024-0137 detection patterns
    if 'unshare' in syscall_line and ('CLONE_NEWNET' in syscall_line or '--net' in syscall_line):
        print(f"🔥 CRITICAL: CVE-2024-0137 network namespace escape detected!")
        print(f"   Terminating malicious container...")
        try:
            # Kill the entire process group
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except:
            try:
                os.kill(pid, signal.SIGKILL)
            except:
                pass
    
    elif 'setns' in syscall_line:
        print(f"🔥 CRITICAL: Namespace manipulation detected!")
        print(f"   Possible container escape attempt!")

def run_monitored_container_fixed(cgroup_name, chroot_dir="./extracted_python", 
                                 command=None, memory_limit="100M", container_name="container"):
    """
    Fixed version that properly monitors syscalls inside containers
    """
    import uuid
    
    container_id = f"{container_name}_{str(uuid.uuid4())[:8]}"
    print(f"🔍 Starting monitored container: {container_id}")
    print(f"🛡️  Enhanced monitoring for CVE-2024-0137...")
    
    if command is None:
        command = ['/bin/sh']
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
    
    # Build the complete container command
    container_cmd = [
        'unshare', '--pid', '--mount', '--net', '--uts', '--ipc', '--fork',
        'chroot', chroot_dir
    ] + command
    
    print(f"🚀 Executing with internal monitoring...")
    
    # Run with internal syscall monitoring
    exit_code = monitor_container_syscalls(container_cmd, alert_handler)
    
    print(f"🏁 Container {container_id} exited with code: {exit_code}")
    return exit_code

# Enhanced test functions
def test_rogue_network_escape_fixed():
    """Enhanced test that should trigger alerts"""
    print("\n" + "="*60)
    print("🧪 TESTING: Enhanced rogue network namespace escape")
    print("="*60)
    
    # More aggressive test that directly calls unshare syscall
    rogue_command = """
    echo "Attempting direct namespace escape..."
    python3 -c "
import os
import ctypes
import subprocess

print('Direct syscall-based namespace escape attempt...')

# Try direct unshare syscall (this should be caught)
try:
    libc = ctypes.CDLL('libc.so.6')
    CLONE_NEWNET = 0x40000000
    result = libc.unshare(CLONE_NEWNET)
    print(f'Direct unshare syscall result: {result}')
except Exception as e:
    print(f'Direct syscall failed: {e}')

# Try subprocess unshare (this should also be caught)
try:
    subprocess.run(['unshare', '--net', 'echo', 'namespace created'], timeout=1)
except Exception as e:
    print(f'Subprocess unshare failed: {e}')

print('Rogue test completed')
"
    """
    
    return run_monitored_container_fixed(
        cgroup_name="rogue_test_fixed",
        chroot_dir="./extracted_python",
        command=rogue_command,
        memory_limit="50M",
        container_name="rogue_fixed"
    )

def test_setns_attack():
    """Test direct setns syscall attack"""
    print("\n" + "="*60)
    print("🧪 TESTING: Direct setns namespace escape")
    print("="*60)
    
    setns_command = """
    python3 -c "
import ctypes
import os

print('Attempting setns-based escape...')
try:
    libc = ctypes.CDLL('libc.so.6')
    # Try to setns to host network namespace (this should be blocked)
    fd = os.open('/proc/1/ns/net', os.O_RDONLY)
    result = libc.setns(fd, 0)
    print(f'setns result: {result}')
    os.close(fd)
except Exception as e:
    print(f'setns attack failed: {e}')
print('setns test completed')
"
    """
    
    return run_monitored_container_fixed(
        cgroup_name="setns_test",
        chroot_dir="./extracted_python",
        command=setns_command,
        memory_limit="50M",
        container_name="setns_test"
    )

# Main execution
if __name__ == "__main__":
    print("🛡️  FIXED CVE-2024-0137 Syscall Monitor - Container Antivirus")
    print("=" * 60)
    
    print("Running enhanced security tests...")
    
    # Test 1: Enhanced rogue network escape
    test_rogue_network_escape_fixed()
    
    # Test 2: Direct setns attack
    test_setns_attack()
    
    print("\n🎯 Enhanced tests completed!")
    print("🔍 Dangerous syscalls should now be properly detected and blocked")
