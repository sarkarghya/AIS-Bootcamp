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
    
    print("Setting up bridge network...")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠ Warning: Bridge network setup requires root privileges")
        return False
    
    try:
        # Enable IP forwarding
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
        print("✓ Enabled IP forwarding")
        
        # Remove existing bridge if it exists
        subprocess.run(['ip', 'link', 'del', 'bridge0'], stderr=subprocess.DEVNULL)
        
        # Create and configure bridge
        subprocess.run(['ip', 'link', 'add', 'bridge0', 'type', 'bridge'], check=True)
        subprocess.run(['ip', 'addr', 'add', '10.0.0.1/24', 'dev', 'bridge0'], check=True)
        subprocess.run(['ip', 'link', 'set', 'bridge0', 'up'], check=True)
        print("✓ Created bridge0 with IP 10.0.0.1/24")
        
        # Clear existing iptables rules
        subprocess.run(['iptables', '-F'])
        subprocess.run(['iptables', '-t', 'nat', '-F'])
        subprocess.run(['iptables', '-t', 'mangle', '-F'])
        subprocess.run(['iptables', '-X'])
        
        # Set default policies
        subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'])
        subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'])
        subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'])
        
        # Get default network interface
        default_iface = subprocess.run(['ip', 'route', 'show', 'default'], 
                                     capture_output=True, text=True).stdout.split()[4]
        print(f"✓ Detected default interface: {default_iface}")
        
        # Add iptables rules for NAT and forwarding
        subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '10.0.0.0/24', 
                       '!', '-o', 'bridge0', '-j', 'MASQUERADE'])
        subprocess.run(['iptables', '-A', 'FORWARD', '-i', 'bridge0', '-o', default_iface, '-j', 'ACCEPT'])
        subprocess.run(['iptables', '-A', 'FORWARD', '-i', default_iface, '-o', 'bridge0', 
                       '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
        subprocess.run(['iptables', '-A', 'FORWARD', '-i', 'bridge0', '-o', 'bridge0', '-j', 'ACCEPT'])
        print("✓ Configured iptables for NAT and forwarding")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"✗ Error setting up bridge network: {e}")
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
        # Shorten names to fit Linux 15-character interface name limit
        # Use hash to create short unique identifier
        short_id = str(hash(container_id) % 10000).zfill(4)  # 4-digit ID
        veth_host = f"veth0_{short_id}"      # e.g., "veth0_1234" (10 chars)
        veth_container = f"veth1_{short_id}" # e.g., "veth1_1234" (10 chars)
        netns_name = f"netns_{short_id}"     # namespace name can be longer
        container_ip = f"10.0.0.{ip_suffix}"
        
        print(f"  Using short interface names: {veth_host} <-> {veth_container}")
        
        # Create veth pair
        subprocess.run(['ip', 'link', 'add', 'dev', veth_host, 'type', 'veth', 
                       'peer', 'name', veth_container], check=True)
        
        # Attach host end to bridge
        subprocess.run(['ip', 'link', 'set', 'dev', veth_host, 'up'], check=True)
        subprocess.run(['ip', 'link', 'set', veth_host, 'master', 'bridge0'], check=True)
        
        # Create network namespace
        subprocess.run(['ip', 'netns', 'add', netns_name], check=True)
        
        # Move container end to namespace
        subprocess.run(['ip', 'link', 'set', veth_container, 'netns', netns_name], check=True)
        
        # Configure container network interface
        subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'link', 'set', 'dev', 'lo', 'up'], check=True)
        subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'addr', 'add', 
                       f'{container_ip}/24', 'dev', veth_container], check=True)
        subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'link', 'set', 
                       'dev', veth_container, 'up'], check=True)
        
        # Add default route
        subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'route', 'add', 
                       'default', 'via', '10.0.0.1'], check=True)
        
        print(f"✓ Created network interface for container {container_id}")
        print(f"  - Container IP: {container_ip}/24")
        print(f"  - Gateway: 10.0.0.1")
        print(f"  - Network namespace: {netns_name}")
        
        return netns_name
        
    except subprocess.CalledProcessError as e:
        print(f"✗ Error creating container network: {e}")
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
        return
    
    try:
        # Use same naming scheme as create_container_network
        short_id = str(hash(container_id) % 10000).zfill(4)
        veth_host = f"veth0_{short_id}"
        netns_name = f"netns_{short_id}"
        
        # Remove network namespace (this also removes the veth pair)
        subprocess.run(['ip', 'netns', 'del', netns_name], stderr=subprocess.DEVNULL)
        
        # Remove host veth if it still exists
        subprocess.run(['ip', 'link', 'del', veth_host], stderr=subprocess.DEVNULL)
        
        print(f"✓ Cleaned up network for container {container_id}")
        
    except Exception as e:
        print(f"⚠ Warning: Could not fully clean up network for {container_id}: {e}")


def test_container_networking():
    """
    Test creating a container with its own network
    This demonstrates how to create a container with:
    - Its own IP address
    - Internet connectivity through bridge
    - Network isolation from host
    """
    print("\n=== Testing Container Networking ===")
    
    # Test container with networking
    print("\n1. Creating container with network connectivity:")
    network_test_commands = [
        "echo 'Container network info:'",
        "hostname container-network-test",
        "ip addr show",
        "echo 'Routing table:'",
        "ip route show",
        "echo 'Testing gateway connectivity:'",
        "ping -c 2 10.0.0.1 || echo 'Gateway unreachable'",
        "echo 'Testing internet connectivity:'",
        "ping -c 2 8.8.8.8 || echo 'Internet unreachable'",
        "echo 'Container network test complete'"
    ]
    
    combined_cmd = "; ".join(network_test_commands)
    
    result = run_in_cgroup_chroot_namespaced(
        cgroup_name="network_test",
        chroot_dir="./extracted_python",
        command=combined_cmd,
        memory_limit="100M"
    )
    
    print(f"\n2. Container network test result: {'SUCCESS' if result == 0 else 'FAILED'}")
    
    return True


# %% Test basic container with networking
def test_basic_container():
    """
    Test creating a basic container similar to Docker run
    """
    print("\n=== Testing Basic Container (like docker run) ===")
    
    container_commands = [
        "echo 'Starting container...'",
        "hostname my-container",
        "echo 'Container hostname: ' && hostname",
        "echo 'Container IP: ' && ip addr show | grep 'inet ' | grep -v '127.0.0.1'",
        "echo 'Running Python in container:'",
        "python3 -c 'print(\"Hello from containerized Python!\")'",
        "echo 'Container complete'"
    ]
    
    combined_cmd = "; ".join(container_commands)
    
    print("\n1. Running basic container:")
    result = run_in_cgroup_chroot_namespaced(
        cgroup_name="basic_container",
        chroot_dir="./extracted_python",
        command=combined_cmd,
        memory_limit="100M"
    )
    
    print(f"\n2. Basic container result: {'SUCCESS' if result == 0 else 'FAILED'}")
    
    return True


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
    
    # Create cgroup
    create_cgroup(cgroup_name, memory_limit=memory_limit)
    
    if command is None:
        command = ['/bin/sh']
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
    
    # Generate unique container ID
    container_id = f"{container_name}_{str(uuid.uuid4())[:8]}"
    ip_suffix = hash(container_id) % 200 + 50  # IP range 10.0.0.50-249
    
    print(f"Creating networked container: {container_id}")
    print(f"Command: {command}")
    print(f"Memory limit: {memory_limit}")
    
    # Set up bridge network
    bridge_ready = setup_bridge_network()
    
    # Create container network
    netns_name = None
    if bridge_ready:
        netns_name = create_container_network(container_id, ip_suffix)
        if netns_name:
            print(f"✓ Container {container_id} assigned IP: 10.0.0.{ip_suffix}/24")
    
    try:
        # Fork to create child process
        pid = os.fork()
        
        if pid == 0:
            # Child process - set up signal handler and wait
            def resume_handler(signum, frame):
                pass
            
            signal.signal(signal.SIGUSR1, resume_handler)
            print(f"Child process {os.getpid()} waiting for setup...")
            signal.pause()  # Wait for SIGUSR1 from parent
            print(f"Child process {os.getpid()} starting container...")
            
            # Build execution command
            if netns_name:
                # Execute with dedicated network namespace
                exec_args = ['ip', 'netns', 'exec', netns_name, 'unshare', 
                           '--pid', '--mount', '--uts', '--ipc', '--fork', 
                           'chroot', chroot_dir] + command
            else:
                # Execute with isolated network namespace (no internet)
                exec_args = ['unshare', '--pid', '--mount', '--net', '--uts', '--ipc', 
                           '--fork', 'chroot', chroot_dir] + command
            
            os.execvp(exec_args[0], exec_args)
            
        else:
            # Parent process - configure container then signal child
            print(f"Configuring container {container_id} (PID: {pid})")
            
            # Add to cgroup
            cgroup_procs_path = f"/sys/fs/cgroup/{cgroup_name}/cgroup.procs"
            with open(cgroup_procs_path, "w") as f:
                f.write(str(pid))
            print(f"✓ Added to cgroup: {cgroup_name}")
            
            # Signal child to start
            os.kill(pid, signal.SIGUSR1)
            print(f"✓ Container {container_id} started")
            
            # Wait for completion
            _, status = os.waitpid(pid, 0)
            exit_code = os.WEXITSTATUS(status)
            
            print(f"Container {container_id} exited with code: {exit_code}")
            
            # Cleanup
            if netns_name:
                cleanup_container_network(container_id)
            
            return exit_code
            
    except Exception as e:
        print(f"Error running networked container: {e}")
        if netns_name:
            cleanup_container_network(container_id)
        return None


def create_isolated_container(cgroup_name, chroot_dir, command=None, memory_limit="100M"):
    """
    Create a container with network isolation (no internet access)
    This demonstrates containers without networking
    """
    import subprocess
    import os
    import signal
    
    # Create cgroup
    create_cgroup(cgroup_name, memory_limit=memory_limit)
    
    if command is None:
        command = ['/bin/sh']
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
    
    print(f"Creating isolated container (no network)")
    print(f"Command: {command}")
    print(f"Memory limit: {memory_limit}")
    
    try:
        # Fork to create child process
        pid = os.fork()
        
        if pid == 0:
            # Child process
            def resume_handler(signum, frame):
                pass
            
            signal.signal(signal.SIGUSR1, resume_handler)
            signal.pause()
            
            # Execute with full isolation including network
            os.execvp('unshare', ['unshare', '--pid', '--mount', '--net', '--uts', '--ipc', 
                                '--fork', 'chroot', chroot_dir] + command)
            
        else:
            # Parent process
            # Add to cgroup
            cgroup_procs_path = f"/sys/fs/cgroup/{cgroup_name}/cgroup.procs"
            with open(cgroup_procs_path, "w") as f:
                f.write(str(pid))
            
            # Signal child to start
            os.kill(pid, signal.SIGUSR1)
            
            # Wait for completion
            _, status = os.waitpid(pid, 0)
            exit_code = os.WEXITSTATUS(status)
            
            print(f"Isolated container exited with code: {exit_code}")
            return exit_code
            
    except Exception as e:
        print(f"Error running isolated container: {e}")
        return None


def test_networked_vs_isolated():
    """
    Test showing the difference between networked and isolated containers
    """
    print("\n=== Testing Networked vs Isolated Containers ===")
    
    network_test_cmd = [
        "echo 'Container network test:'",
        "hostname networked-container", 
        "ip addr show | head -10",
        "ping -c 2 8.8.8.8 || echo 'No internet access'",
        "echo 'Network test complete'"
    ]
    
    isolation_test_cmd = [
        "echo 'Isolated container test:'",
        "hostname isolated-container",
        "ip addr show | head -10 || echo 'No network interfaces'", 
        "ping -c 1 8.8.8.8 || echo 'No internet access (expected)'",
        "echo 'Isolation test complete'"
    ]
    
    print("\n1. Testing NETWORKED container (with internet):")
    run_networked_container(
        cgroup_name="networked_test",
        chroot_dir="./extracted_python",
        command="; ".join(network_test_cmd),
        memory_limit="100M",
        container_name="networked"
    )
    
    print("\n2. Testing ISOLATED container (no internet):")
    create_isolated_container(
        cgroup_name="isolated_test", 
        chroot_dir="./extracted_python",
        command="; ".join(isolation_test_cmd),
        memory_limit="100M"
    )
    
    print("\n=== Container comparison complete ===")
    return True


# %% Execute networking tests

# %% Execute networking tests
print("\n" + "="*50)
print("TESTING NETWORKED vs ISOLATED CONTAINERS")
print("="*50)

test_networked_vs_isolated()

print("\n" + "="*50)
print("TESTING NETWORKED CONTAINER")
print("="*50)

print("Creating a networked container with Python:")
run_networked_container(
    cgroup_name="python_networked",
    chroot_dir="./extracted_python", 
    command="python3 -c 'import socket; print(f\"Container can resolve: {socket.gethostbyname(\"google.com\")}\"); print(\"Networked Python container working!\")'",
    memory_limit="100M",
    container_name="python_demo"
)

print("\n" + "="*50)
print("TESTING ISOLATED CONTAINER")
print("="*50)

print("Creating an isolated container:")
create_isolated_container(
    cgroup_name="python_isolated",
    chroot_dir="./extracted_python",
    command="python3 -c 'print(\"Isolated Python container working!\"); import os; print(f\"PID: {os.getpid()}\")'",
    memory_limit="100M"
)
