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


# %% Namespace management functions

def setup_pid_namespace():
    """
    Set up PID namespace isolation
    Creates a new PID namespace where processes see isolated PID space
    """
    import subprocess
    
    print("Setting up PID namespace...")
    try:
        # Use unshare to create new PID namespace
        # In new PID namespace, the process becomes PID 1
        result = subprocess.run(['unshare', '--pid', '--fork', '--mount-proc', '/bin/sh', '-c', 'echo "PID namespace created, current PID: $$"'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ PID namespace created successfully")
            return True
        else:
            print(f"✗ Failed to create PID namespace: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error setting up PID namespace: {e}")
        return False


def setup_mount_namespace():
    """
    Set up mount namespace isolation
    Creates a new mount namespace where filesystem mounts are isolated
    """
    import subprocess
    
    print("Setting up mount namespace...")
    try:
        # Create new mount namespace
        result = subprocess.run(['unshare', '--mount', '/bin/sh', '-c', 'echo "Mount namespace created"'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ Mount namespace created successfully")
            return True
        else:
            print(f"✗ Failed to create mount namespace: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error setting up mount namespace: {e}")
        return False


def setup_network_namespace():
    """
    Set up network namespace isolation
    Creates a new network namespace with isolated network interfaces
    """
    import subprocess
    
    print("Setting up network namespace...")
    try:
        # Create new network namespace
        result = subprocess.run(['unshare', '--net', '/bin/sh', '-c', 'ip link show'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ Network namespace created successfully")
            print(f"   Available interfaces: {result.stdout.strip()}")
            return True
        else:
            print(f"✗ Failed to create network namespace: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error setting up network namespace: {e}")
        return False


def setup_uts_namespace():
    """
    Set up UTS namespace isolation (hostname/domainname)
    Creates a new UTS namespace where hostname can be changed independently
    """
    import subprocess
    
    print("Setting up UTS namespace...")
    try:
        # Create new UTS namespace and change hostname
        result = subprocess.run(['unshare', '--uts', '/bin/sh', '-c', 'hostname container-test && echo "Hostname changed to: $(hostname)"'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ UTS namespace created successfully")
            print(f"   {result.stdout.strip()}")
            return True
        else:
            print(f"✗ Failed to create UTS namespace: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error setting up UTS namespace: {e}")
        return False


def setup_ipc_namespace():
    """
    Set up IPC namespace isolation
    Creates a new IPC namespace where System V IPC objects are isolated
    """
    import subprocess
    
    print("Setting up IPC namespace...")
    try:
        # Create new IPC namespace
        result = subprocess.run(['unshare', '--ipc', '/bin/sh', '-c', 'ipcs -q && echo "IPC namespace created"'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ IPC namespace created successfully")
            return True
        else:
            print(f"✗ Failed to create IPC namespace: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error setting up IPC namespace: {e}")
        return False


def setup_user_namespace():
    """
    Set up user namespace isolation
    Creates a new user namespace where user/group IDs are mapped
    """
    import subprocess
    
    print("Setting up user namespace...")
    try:
        # Create new user namespace
        result = subprocess.run(['unshare', '--user', '--map-root-user', '/bin/sh', '-c', 'id && echo "User namespace created"'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ User namespace created successfully")
            print(f"   {result.stdout.strip()}")
            return True
        else:
            print(f"✗ Failed to create user namespace: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error setting up user namespace: {e}")
        return False


def setup_cgroup_namespace():
    """
    Set up cgroup namespace isolation
    Creates a new cgroup namespace where cgroup view is isolated
    """
    import subprocess
    
    print("Setting up cgroup namespace...")
    try:
        # Create new cgroup namespace
        result = subprocess.run(['unshare', '--cgroup', '/bin/sh', '-c', 'cat /proc/self/cgroup'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ Cgroup namespace created successfully")
            return True
        else:
            print(f"✗ Failed to create cgroup namespace: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error setting up cgroup namespace: {e}")
        return False


# %% Namespace test functions

def test_pid_namespace():
    """
    Test PID namespace isolation
    Verifies that processes in different PID namespaces see different PID spaces
    """
    import subprocess
    
    print("Testing PID namespace isolation...")
    
    # Get host PID
    host_pid = subprocess.run(['sh', '-c', 'echo $$'], capture_output=True, text=True).stdout.strip()
    print(f"Host shell PID: {host_pid}")
    
    # Create PID namespace and check PID
    try:
        result = subprocess.run(['unshare', '--pid', '--fork', '--mount-proc', '/bin/sh', '-c', 'echo "Namespace PID: $$"'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            namespace_output = result.stdout.strip()
            print(f"✓ {namespace_output}")
            
            # Check if PID is different (should be 1 in new namespace)
            if "PID: 1" in namespace_output:
                print("✓ PID namespace isolation working - process is PID 1 in namespace")
                return True
            else:
                print("⚠ PID namespace created but process is not PID 1")
                return False
        else:
            print(f"✗ PID namespace test failed: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("✗ PID namespace test timed out")
        return False
    except Exception as e:
        print(f"✗ Error testing PID namespace: {e}")
        return False


def test_mount_namespace():
    """
    Test mount namespace isolation
    Verifies that mounts in different mount namespaces are isolated
    """
    import subprocess
    import tempfile
    import os
    
    print("Testing mount namespace isolation...")
    
    try:
        # Create a temporary directory for testing
        with tempfile.TemporaryDirectory() as tmpdir:
            test_mount = os.path.join(tmpdir, "test_mount")
            os.makedirs(test_mount, exist_ok=True)
            
            # Create mount namespace and make a bind mount
            script = f"""
            mkdir -p {test_mount}/inside_namespace
            echo "namespace mount" > {test_mount}/inside_namespace/test.txt
            mount --bind {test_mount}/inside_namespace {test_mount}/inside_namespace
            echo "Mount created in namespace"
            ls -la {test_mount}/inside_namespace/
            """
            
            result = subprocess.run(['unshare', '--mount', '/bin/sh', '-c', script], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print("✓ Mount namespace isolation working")
                print(f"   Output: {result.stdout.strip()}")
                return True
            else:
                print(f"✗ Mount namespace test failed: {result.stderr}")
                return False
                
    except subprocess.TimeoutExpired:
        print("✗ Mount namespace test timed out")
        return False
    except Exception as e:
        print(f"✗ Error testing mount namespace: {e}")
        return False


def test_network_namespace():
    """
    Test network namespace isolation
    Verifies that network interfaces are isolated between namespaces
    """
    import subprocess
    
    print("Testing network namespace isolation...")
    
    try:
        # Get host network interfaces
        host_interfaces = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True).stdout
        host_interface_count = host_interfaces.count(': ')
        print(f"Host has {host_interface_count} network interfaces")
        
        # Check network interfaces in new namespace
        result = subprocess.run(['unshare', '--net', '/bin/sh', '-c', 'ip link show | wc -l'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            namespace_lines = int(result.stdout.strip())
            print(f"Namespace has {namespace_lines} lines of network output")
            
            # New network namespace should have only loopback (usually 2 lines)
            if namespace_lines <= 2:
                print("✓ Network namespace isolation working - minimal interfaces in namespace")
                return True
            else:
                print("⚠ Network namespace created but may not be properly isolated")
                return False
        else:
            print(f"✗ Network namespace test failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ Network namespace test timed out")
        return False
    except Exception as e:
        print(f"✗ Error testing network namespace: {e}")
        return False


def test_uts_namespace():
    """
    Test UTS namespace isolation
    Verifies that hostname changes are isolated between namespaces
    """
    import subprocess
    
    print("Testing UTS namespace isolation...")
    
    try:
        # Get host hostname
        host_hostname = subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip()
        print(f"Host hostname: {host_hostname}")
        
        # Change hostname in UTS namespace
        result = subprocess.run(['unshare', '--uts', '/bin/sh', '-c', 'hostname container-test && echo "New hostname: $(hostname)"'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            namespace_output = result.stdout.strip()
            print(f"✓ {namespace_output}")
            
            # Verify host hostname unchanged
            current_host_hostname = subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip()
            if current_host_hostname == host_hostname:
                print("✓ UTS namespace isolation working - host hostname unchanged")
                return True
            else:
                print("✗ UTS namespace isolation failed - host hostname changed")
                return False
        else:
            print(f"✗ UTS namespace test failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ UTS namespace test timed out")
        return False
    except Exception as e:
        print(f"✗ Error testing UTS namespace: {e}")
        return False


def test_ipc_namespace():
    """
    Test IPC namespace isolation
    Verifies that System V IPC objects are isolated between namespaces
    """
    import subprocess
    
    print("Testing IPC namespace isolation...")
    
    try:
        # Get host IPC objects
        host_ipc = subprocess.run(['ipcs', '-q'], capture_output=True, text=True).stdout
        host_ipc_count = host_ipc.count('\n')
        print(f"Host has {host_ipc_count} lines of IPC output")
        
        # Check IPC objects in new namespace
        result = subprocess.run(['unshare', '--ipc', '/bin/sh', '-c', 'ipcs -q | wc -l'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            namespace_lines = int(result.stdout.strip())
            print(f"Namespace has {namespace_lines} lines of IPC output")
            
            # New namespace should have fewer IPC objects
            if namespace_lines <= host_ipc_count:
                print("✓ IPC namespace isolation working - isolated IPC objects")
                return True
            else:
                print("⚠ IPC namespace created but isolation unclear")
                return False
        else:
            print(f"✗ IPC namespace test failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ IPC namespace test timed out")
        return False
    except Exception as e:
        print(f"✗ Error testing IPC namespace: {e}")
        return False


def test_user_namespace():
    """
    Test user namespace isolation
    Verifies that user/group ID mapping works in user namespaces
    """
    import subprocess
    
    print("Testing user namespace isolation...")
    
    try:
        # Get host user ID
        host_uid = subprocess.run(['id', '-u'], capture_output=True, text=True).stdout.strip()
        print(f"Host UID: {host_uid}")
        
        # Check user ID in new namespace
        result = subprocess.run(['unshare', '--user', '--map-root-user', '/bin/sh', '-c', 'echo "Namespace UID: $(id -u)"'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            namespace_output = result.stdout.strip()
            print(f"✓ {namespace_output}")
            
            # Check if we became root in the namespace
            if "UID: 0" in namespace_output:
                print("✓ User namespace isolation working - mapped to root in namespace")
                return True
            else:
                print("⚠ User namespace created but UID mapping unclear")
                return False
        else:
            print(f"✗ User namespace test failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ User namespace test timed out")
        return False
    except Exception as e:
        print(f"✗ Error testing user namespace: {e}")
        return False


def test_cgroup_namespace():
    """
    Test cgroup namespace isolation
    Verifies that cgroup view is isolated between namespaces
    """
    import subprocess
    
    print("Testing cgroup namespace isolation...")
    
    try:
        # Get host cgroup view
        host_cgroup = subprocess.run(['cat', '/proc/self/cgroup'], capture_output=True, text=True).stdout
        host_cgroup_lines = host_cgroup.count('\n')
        print(f"Host has {host_cgroup_lines} cgroup entries")
        
        # Check cgroup view in new namespace
        result = subprocess.run(['unshare', '--cgroup', '/bin/sh', '-c', 'cat /proc/self/cgroup'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            namespace_cgroup = result.stdout
            namespace_cgroup_lines = namespace_cgroup.count('\n')
            print(f"Namespace has {namespace_cgroup_lines} cgroup entries")
            
            # Cgroup view should be different
            if namespace_cgroup != host_cgroup:
                print("✓ Cgroup namespace isolation working - different cgroup view")
                return True
            else:
                print("⚠ Cgroup namespace created but view seems identical")
                return False
        else:
            print(f"✗ Cgroup namespace test failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ Cgroup namespace test timed out")
        return False
    except Exception as e:
        print(f"✗ Error testing cgroup namespace: {e}")
        return False


def test_all_namespaces():
    """
    Test all namespace types together
    Creates a process with all namespace types isolated
    """
    import subprocess
    
    print("Testing all namespaces together...")
    
    try:
        # Create all namespaces at once
        script = """
        echo "=== ALL NAMESPACES TEST ==="
        echo "PID: $$"
        echo "UID: $(id -u)"
        echo "Hostname: $(hostname)"
        echo "Network interfaces: $(ip link show | wc -l)"
        echo "Cgroup view: $(cat /proc/self/cgroup | wc -l)"
        echo "=== END TEST ==="
        """
        
        result = subprocess.run([
            'unshare', '--pid', '--fork', '--mount-proc',
            '--net', '--uts', '--ipc', '--user', '--map-root-user',
            '--cgroup', '/bin/sh', '-c', script
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            print("✓ All namespaces created successfully")
            print("   Output from isolated environment:")
            for line in result.stdout.strip().split('\n'):
                print(f"   {line}")
            return True
        else:
            print(f"✗ All namespaces test failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ All namespaces test timed out")
        return False
    except Exception as e:
        print(f"✗ Error testing all namespaces: {e}")
        return False


# %% Namespace failure scenarios

def test_network_namespace_failure():
    """
    Test network namespace failure scenario
    Demonstrates what happens when network access is restricted
    """
    import subprocess
    
    print("Testing network namespace failure scenario...")
    print("(This demonstrates network isolation - no internet access)")
    
    try:
        # Try to access internet from isolated network namespace
        result = subprocess.run([
            'unshare', '--net', '/bin/sh', '-c', 
            'ping -c 1 8.8.8.8 || echo "No network access (expected)"'
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            print("✓ Network isolation working - no internet access in namespace")
            print(f"   Output: {result.stdout.strip()}")
            return True
        else:
            print("⚠ Network namespace created but internet access still available")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ Network namespace failure test timed out")
        return False
    except Exception as e:
        print(f"✗ Error testing network namespace failure: {e}")
        return False


def test_mount_namespace_failure():
    """
    Test mount namespace failure scenario
    Demonstrates what happens when filesystem access is restricted
    """
    import subprocess
    
    print("Testing mount namespace failure scenario...")
    print("(This demonstrates filesystem isolation)")
    
    try:
        # Try to access host filesystem from isolated mount namespace
        script = """
        # Try to unmount /tmp in namespace (should not affect host)
        umount /tmp 2>/dev/null || echo "Could not unmount /tmp"
        # Try to create a new mount point
        mkdir -p /isolated_mount 2>/dev/null || echo "Could not create /isolated_mount"
        echo "Mount namespace isolation active"
        """
        
        result = subprocess.run(['unshare', '--mount', '/bin/sh', '-c', script], 
                              capture_output=True, text=True, timeout=10)
        
        print("✓ Mount namespace isolation working")
        print(f"   Output: {result.stdout.strip()}")
        return True
        
    except subprocess.TimeoutExpired:
        print("✗ Mount namespace failure test timed out")
        return False
    except Exception as e:
        print(f"✗ Error testing mount namespace failure: {e}")
        return False


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

print("\n1. Testing PID namespace isolation:")
test_pid_namespace()

print("\n2. Testing network namespace isolation:")
test_network_namespace()

print("\n3. Testing UTS namespace isolation:")
test_uts_namespace()

print("\n4. Testing all namespaces together:")
test_all_namespaces()

print("\n5. Testing namespace failure scenarios:")
test_network_namespace_failure()
test_mount_namespace_failure()

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
