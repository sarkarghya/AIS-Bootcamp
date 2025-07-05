# %%
"""
# Containers and Isolation

#### Introduction to Containers and System Isolation

In this exercise, you'll learn about the fundamental building blocks of container technology by implementing a simplified container runtime. You will manually download and extract Docker image layers, then use Linux system isolation features like chroot and cgroups to create isolated environments similar to what Docker provides.

- Make a new file called w2d2.py, and copy the code snippets from this file into it as you are progressing through the instructions.
- For the sake of the exercise, aim for correctness and understanding, not efficiency.

<!-- toc -->

# 1. Container Layer Extraction

In this exercise, you'll learn how Docker images are structured and how to manually download and extract their layers. This will give you a deep understanding of how container images work under the hood.

## Introduction

Docker images are composed of multiple layers that are stacked on top of each other to create the final filesystem. Each layer represents a change to the filesystem - whether it's adding files, modifying existing ones, or removing them.
These layers are stored in container registries like Docker Hub as compressed tar archives (tarballs).
When you run `docker pull`, Docker downloads these layers, extracts them, and overlays them to create the final container filesystem.
Understanding this process is crucial for understanding how containers work at a low level.

The Docker registry API follows a specific protocol for downloading images:
1. First, you request a manifest that describes the image and its layers
2. For multi-architecture images, you need to find the manifest for your specific architecture
3. Each layer is identified by a cryptographic digest (SHA-256 hash)
4. You download each layer as a gzipped tar archive
5. Finally, you extract each layer in order to build the complete filesystem

Container images are built using a copy-on-write (COW) filesystem approach, where each layer only contains the differences from the previous layer.
This makes images efficient to store and transfer, as common base layers (like the Ubuntu base image) can be shared between multiple images.
The layered approach also enables efficient caching during the build process and faster image pulls when layers are already present locally.

## Content & Learning Objectives

### 1️⃣ Docker Registry API

In the first exercise, you'll implement functions to interact with the Docker registry API to download image manifests and layers.

> **Learning Objectives**
> - Understand the Docker registry API protocol
> - Learn how multi-architecture images are handled
> - Implement authentication for Docker Hub

### 2️⃣ Layer Extraction

Here, you'll implement the extraction of Docker image layers to build a complete filesystem.

> **Learning Objectives**
> - Understand how Docker layers are structured
> - Implement tar archive extraction
> - Build a complete container filesystem from layers

<details>
<summary>Vocabulary: Container Terms</summary>

- **Container image**: A lightweight, standalone package that includes everything needed to run an application
- **Layer**: A single filesystem change in a container image
- **Manifest**: A JSON document that describes the components of a container image
- **Digest**: A cryptographic hash (SHA-256) that uniquely identifies a layer or manifest
- **Registry**: A storage and content delivery system for container images
- **Tarball**: A compressed archive file containing multiple files and directories

</details>
"""

# %%
"""
## Exercise 1.1: Implementing Docker Registry API Client

The Docker registry API allows you to download container images programmatically. You'll need to handle authentication, manifest retrieval, and layer downloading.

### Exercise - implement pull_layers

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~30 minutes on this exercise.

Implement the `pull_layers` function that downloads and extracts Docker image layers.
"""

import requests
import tarfile
import json
import sys
import os
import platform
from io import BytesIO
from typing import Optional

# Architecture selection
# For macOS on Apple Silicon (M1/M2/M3)
TARGET_ARCH = "arm64"
TARGET_VARIANT = "v8"

def pull_layers(image_ref: str, output_dir: str, target_arch: str = TARGET_ARCH, target_variant: Optional[str] = TARGET_VARIANT) -> None:
    """
    Pull and extract Docker image layers for a specific architecture.

    This function implements the Docker registry API protocol:
    1. Parse the image reference to extract registry, image name, and tag
    2. Get authentication token for Docker Hub if needed
    3. Fetch the manifest list to find architecture-specific manifest
    4. Download each layer and extract it to the output directory

    Args:
        image_ref: Can be:
            - Full URL: https://registry-1.docker.io/v2/library/hello-world/manifests/latest
            - Docker Hub format: hello-world:latest or library/hello-world:latest
            - Other registry: gcr.io/google-containers/pause:latest
        output_dir: Directory to extract layers to
        target_arch: Target architecture (e.g., "arm64", "amd64")
        target_variant: Architecture variant (e.g., "v8" for arm64)
    """
    if "SOLUTION":
        print(f"Detected architecture: {target_arch} {target_variant if target_variant else ''}")
        
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
        print(f"Target architecture: {target_arch}{f' variant {target_variant}' if target_variant else ''}")

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Get auth token for Docker Hub if needed
        headers = {}
        if registry == 'registry-1.docker.io':
            token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
            token_resp = requests.get(token_url)
            token_resp.raise_for_status()
            token = token_resp.json()['token']
            headers['Authorization'] = f'Bearer {token}'

        # Step 1: Get manifest list
        manifest_list_url = f"https://{registry}/v2/{image}/manifests/{tag}"
        print(f"\nFetching manifest list from: {manifest_list_url}")

        resp = requests.get(manifest_list_url, headers=headers)
        resp.raise_for_status()
        manifest_list = resp.json()

        # Step 2: Find the manifest for our target architecture
        target_manifest = None
        for manifest in manifest_list.get('manifests', []):
            platform_info = manifest.get('platform', {})
            if platform_info.get('architecture') == target_arch:
                # Check variant if specified
                if target_variant:
                    if platform_info.get('variant') == target_variant:
                        target_manifest = manifest
                        break
                else:
                    # No variant specified, take the first match
                    target_manifest = manifest
                    break

        if not target_manifest:
            print(f"\nError: No manifest found for architecture {target_arch}{f' variant {target_variant}' if target_variant else ''}")
            print("\nAvailable architectures:")
            for manifest in manifest_list.get('manifests', []):
                platform_info = manifest.get('platform', {})
                print(f"  - {platform_info.get('architecture')} {platform_info.get('variant', '')}")
            return

        manifest_digest = target_manifest['digest']
        print(f"\nFound manifest for {target_arch}: {manifest_digest}")

        # Step 3: Get the actual manifest using the digest
        manifest_url = f"https://{registry}/v2/{image}/manifests/{manifest_digest}"
        headers['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json'

        print(f"Fetching manifest from: {manifest_url}")
        resp = requests.get(manifest_url, headers=headers)
        resp.raise_for_status()
        manifest = resp.json()

        print(f"\nManifest type: {manifest.get('mediaType', 'unknown')}")
        print(f"Number of layers: {len(manifest.get('layers', []))}")

        # Step 4: Download and extract layers in order
        for i, layer in enumerate(manifest.get('layers', [])):
            digest = layer['digest']
            size = layer.get('size', 0)
            print(f"\nProcessing layer {i + 1}/{len(manifest['layers'])}: {digest} ({size} bytes)")

            # Download layer blob
            blob_url = f"https://{registry}/v2/{image}/blobs/{digest}"
            blob_resp = requests.get(blob_url, headers=headers, stream=True)
            blob_resp.raise_for_status()

            # Extract layer (layers are gzipped tarballs)
            print(f"  Extracting to {output_dir}...")
            with tarfile.open(fileobj=BytesIO(blob_resp.content), mode='r:gz') as tar:
                tar.extractall(output_dir)

        print(f"\n✓ Extracted {len(manifest.get('layers', []))} layers to {output_dir}")
        print(f"  Architecture: {target_arch}{f' variant {target_variant}' if target_variant else ''}")
    else:
        # TODO: Implement Docker registry API client
        #   - Parse image reference to extract registry, image, and tag
        #   - Get authentication token for Docker Hub
        #   - Fetch manifest list and find architecture-specific manifest
        #   - Download and extract each layer
        #
        # Hints:
        # 1. Handle both Docker Hub format (image:tag) and full URLs
        # 2. For Docker Hub, add "library/" prefix if no namespace
        # 3. Use requests.get() to fetch manifests and layers
        # 4. Extract layers using tarfile.open() with BytesIO
        pass


def test_pull_layers():
    """Test the pull_layers function."""
    print("Testing Docker layer extraction...")
    
    # Test with a small image
    test_image = "alpine:latest"
    test_output = "./test_extracted_alpine"
    
    print(f"Pulling layers for {test_image}...")
    pull_layers(test_image, test_output)
    
    # Verify extraction worked
    assert os.path.exists(test_output), "Output directory was not created"
    assert os.path.exists(os.path.join(test_output, "etc")), "Expected /etc directory not found"
    assert os.path.exists(os.path.join(test_output, "bin")), "Expected /bin directory not found"
    
    print("✓ Layer extraction test passed!\n" + "=" * 60)

# Run the test
test_pull_layers()

# %%
"""
## Extract Some Real Images

Let's extract some real Docker images to use in the next exercise.
"""

# Extract Alpine Linux (minimal Linux distribution)
print("Extracting Alpine Linux...")
pull_layers("alpine:latest", "./extracted_alpine")

# Extract Python 3.12 Alpine image
print("\nExtracting Python 3.12 Alpine...")  
pull_layers("python:3.12-alpine", "./extracted_python")

# %%
"""
# 2. Container Isolation with Chroot and Cgroups

In this exercise, you'll implement the core isolation mechanisms that make containers secure and resource-controlled. You'll use chroot for filesystem isolation and cgroups for resource management.

## Introduction

Container isolation is achieved through several Linux kernel features that work together to create secure, isolated environments.
The two most fundamental mechanisms are chroot and cgroups.

**Chroot (change root)** is a Unix system call that changes the apparent root directory for the running process and its children.
A program that runs in a chrooted environment cannot access files outside the designated directory tree.
This creates filesystem isolation - the process thinks the chroot directory is the entire filesystem.
While chroot provides basic isolation, it's not a complete security mechanism by itself, as processes can still escape with sufficient privileges.
However, when combined with other isolation mechanisms, it forms the foundation of container filesystem isolation.

**Cgroups (control groups)** are a Linux kernel feature that allows you to allocate and limit system resources (CPU, memory, disk I/O, etc.) for groups of processes.
Cgroups provide both resource limiting and monitoring capabilities.
They work hierarchically - you can create nested groups with different resource limits.
For containers, cgroups ensure that a container cannot consume more resources than allocated, preventing one container from affecting others on the same system.
Modern container runtimes like Docker use cgroups extensively to implement resource quotas and limits.

Together, chroot and cgroups provide the foundation for container isolation:
- Chroot isolates the filesystem view
- Cgroups limit and control resource usage
- Additional mechanisms like namespaces (not covered here) provide further isolation

## Content & Learning Objectives

### 2️⃣ Chroot Implementation

In this exercise, you'll implement chroot functionality to create isolated filesystem environments.

> **Learning Objectives**
> - Understand how chroot provides filesystem isolation
> - Implement subprocess management with chroot
> - Test isolated environments with extracted container filesystems

### 3️⃣ Cgroups for Resource Control

Here, you'll implement cgroup management to control resource usage of isolated processes.

> **Learning Objectives**
> - Understand Linux cgroups and resource management
> - Implement memory and CPU limits
> - Combine chroot and cgroups for complete container-like isolation

<details>
<summary>Vocabulary: Isolation Terms</summary>

- **Chroot**: Changes the apparent root directory for a process, isolating its filesystem view
- **Cgroups**: Linux kernel feature for resource management and process grouping
- **Resource limits**: Constraints on CPU, memory, disk I/O, etc. that processes can use
- **Process isolation**: Separating processes so they cannot interfere with each other
- **Namespace**: Linux kernel feature that provides different views of system resources
- **Container runtime**: Software that manages the lifecycle of containers

</details>
"""

# %%
"""
## Exercise 2.1: Implementing Chroot Functionality

Chroot allows you to run processes in an isolated filesystem environment. This is a key component of container isolation.

### Exercise - implement run_chroot

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~20 minutes on this exercise.

Implement the `run_chroot` function that executes commands in a chrooted environment.
"""

import subprocess
import os

def run_chroot(chroot_dir: str, command: Optional[str] = None) -> subprocess.CompletedProcess:
    """
    Run a command in a chrooted environment.
    
    This function uses the chroot system call to change the root directory
    for the executed command, providing filesystem isolation.
    
    Args:
        chroot_dir: Directory to chroot into (must contain a valid filesystem)
        command: Command to run (default: /bin/sh for interactive shell)
    
    Returns:
        CompletedProcess object with execution results
    """
    if "SOLUTION":
        if command is None:
            command_list = ['/bin/sh']
        elif isinstance(command, str):
            command_list = ['/bin/sh', '-c', command]
        else:
            command_list = command
        
        print(f"Running chroot {chroot_dir} with command: {' '.join(command_list)}")
        
        try:
            result = subprocess.run(['chroot', chroot_dir] + command_list, 
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
    else:
        # TODO: Implement chroot command execution
        #   - Handle different command formats (string vs list)
        #   - Use subprocess.run with chroot command
        #   - Include proper error handling and timeouts
        #
        # Hints:
        # 1. Use subprocess.run(['chroot', chroot_dir] + command_list)
        # 2. Set capture_output=True to capture stdout/stderr
        # 3. Use timeout to prevent hanging
        # 4. Handle both string commands and command lists
        pass


def test_chroot_basic():
    """Test basic chroot functionality."""
    print("Testing basic chroot functionality...")
    
    # Test with Alpine Linux
    result = run_chroot("./extracted_alpine", "echo 'Hello from chroot!'")
    assert result and result.returncode == 0, "Basic chroot test failed"
    assert "Hello from chroot!" in result.stdout, "Expected output not found"
    
    # Test file system isolation
    result = run_chroot("./extracted_alpine", "ls /")
    assert result and result.returncode == 0, "Chroot ls test failed"
    # Should see Alpine filesystem, not host filesystem
    assert "etc" in result.stdout, "Expected /etc directory not found in chroot"
    
    print("✓ Basic chroot tests passed!\n" + "=" * 60)

test_chroot_basic()


def test_python_chroot():
    result = run_chroot("./extracted_python", "python --version")
    assert result and result.returncode == 0, "Python chroot test failed"
    assert "Python 3.12" in result.stdout, "Expected Python 3.12 not found"
    
    print(f"✓ Python version in chroot: {result.stdout.strip()}")
    print("✓ Python chroot test passed!\n" + "=" * 60)

test_python_chroot()

# %%
"""
## Exercise 2.3: Implementing Cgroups for Resource Control

Cgroups allow you to limit and control resource usage of processes. This is essential for container isolation and resource management.

### Exercise - implement create_cgroup and run_in_cgroup_chroot

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~25 minutes on this exercise.

Implement cgroup management functions for resource control.
"""

def create_cgroup(cgroup_name: str, memory_limit: Optional[str] = None, cpu_limit: Optional[str] = None) -> str:
    """
    Create a cgroup with specified resource limits.
    
    This function creates a new cgroup in the Linux cgroup filesystem
    and sets resource limits as specified.
    
    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
        cpu_limit: CPU limit (not implemented in this exercise)
    
    Returns:
        Path to the created cgroup directory
    """
    if "SOLUTION":
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
    else:
        # TODO: Implement cgroup creation
        #   - Create cgroup directory in /sys/fs/cgroup/
        #   - Enable controllers in parent cgroup
        #   - Set memory limit if specified
        #
        # Hints:
        # 1. Use os.makedirs() to create the cgroup directory
        # 2. Write to /sys/fs/cgroup/cgroup.subtree_control to enable controllers
        # 3. Write to {cgroup_path}/memory.max to set memory limit
        # 4. Handle exceptions gracefully
        pass


def run_in_cgroup_chroot(cgroup_name: str, chroot_dir: str, command: Optional[str] = None, memory_limit: str = "100M") -> subprocess.CompletedProcess:
    """
    Run a command in both a cgroup and chroot environment.
    
    This function combines cgroup resource limits with chroot filesystem isolation
    to create a container-like environment.
    
    Args:
        cgroup_name: Name of the cgroup to create/use
        chroot_dir: Directory to chroot into
        command: Command to run (default: /bin/sh)
        memory_limit: Memory limit for the cgroup
    
    Returns:
        CompletedProcess object with execution results
    """
    if "SOLUTION":
        # Create cgroup with memory limit
        create_cgroup(cgroup_name, memory_limit=memory_limit)
        
        if command is None:
            command_list = ['/bin/sh']
        elif isinstance(command, str):
            command_list = ['/bin/sh', '-c', command]
        else:
            command_list = command
        
        # Create a shell script that adds the process to cgroup then chroots
        script = f"""
        echo $$ > /sys/fs/cgroup/{cgroup_name}/cgroup.procs
        chroot {chroot_dir} {' '.join(command_list)}
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
    else:
        # TODO: Implement cgroup + chroot execution
        #   - Create cgroup with memory limit
        #   - Create script that adds process to cgroup and chroots
        #   - Execute the script with proper error handling
        #
        # Hints:
        # 1. Use create_cgroup() to set up the cgroup
        # 2. Create a shell script that:
        #    - Adds current process to cgroup: echo $$ > /sys/fs/cgroup/{name}/cgroup.procs
        #    - Runs chroot command
        # 3. Execute with subprocess.run(['sh', '-c', script])
        pass


def test_cgroup_memory_limit():
    """Test memory allocation with cgroup limits."""
    print("Testing cgroup memory limits...")
    
    # Test with a memory-intensive Python script
    python_code = '''
import random
data = []
for i in range(100):
    # Use random data to prevent optimization
    data.append(str(random.random()) * 1024 * 1024)  # 1MB chunks
    print(f"Allocated {i+1}MB", flush=True)
'''
    
    print("Testing memory allocation with 10MB limit (should be killed)...")
    result = run_in_cgroup_chroot(
        cgroup_name="test_demo",
        chroot_dir="./extracted_python",
        command=f"python3 -c '{python_code}'",
        memory_limit="10M"
    )
    
    # The process should be killed by the OOM killer
    assert result.returncode != 0, "Process should have been killed by memory limit"
    print("✓ Memory limit test passed - process was killed as expected")
    
    print("✓ Cgroup tests passed!\n" + "=" * 60)

test_cgroup_memory_limit()

# %%
"""
## Summary: Container Fundamentals

Through these exercises, you've learned the fundamental building blocks of container technology:

### 1. Container Images and Layers
- **Layer Architecture**: Container images are built from multiple layers, each representing filesystem changes
- **Registry Protocol**: Docker registries use a REST API for downloading manifests and layers
- **Multi-Architecture Support**: Images can support multiple CPU architectures in a single reference

### 2. Filesystem Isolation with Chroot
- **Root Directory Isolation**: Chroot changes the apparent root directory for processes
- **Security Boundaries**: While not complete isolation, chroot prevents access to files outside the designated tree
- **Container Filesystems**: Real container images can be extracted and used with chroot

### 3. Resource Control with Cgroups
- **Resource Limits**: Cgroups allow setting limits on memory, CPU, and other resources
- **Process Grouping**: Multiple processes can be managed together as a group
- **Enforcement**: The kernel enforces limits and can kill processes that exceed them

### Real-World Container Technology

Modern container runtimes like Docker use these same principles but with additional features:
- **Namespaces**: Isolate process IDs, network interfaces, and more
- **Union Filesystems**: Efficiently layer filesystems for copy-on-write behavior
- **Container Orchestration**: Tools like Kubernetes manage containers across multiple hosts
- **Security**: Additional mechanisms like seccomp, AppArmor, and SELinux

### Key Takeaways

1. **Containers are not VMs**: They share the host kernel but provide isolation through Linux features
2. **Layered Architecture**: Efficient storage and transfer through filesystem layers
3. **Resource Management**: Cgroups provide fine-grained control over system resources
4. **Filesystem Isolation**: Chroot provides basic filesystem isolation
5. **API Standards**: Container registries follow standardized APIs for interoperability

Understanding these fundamentals helps you:
- Debug container issues more effectively
- Optimize container images and resource usage
- Understand container security implications
- Build your own container tools and runtimes

<details>
<summary>Next Steps</summary>

To continue learning about containers:
- Study Linux namespaces for additional isolation
- Learn about container orchestration with Kubernetes
- Explore container security best practices
- Understand container networking and storage
- Build your own container runtime

</details>
"""

# %%
"""
### Bonus: Advanced Container Features

If you want to explore further, try implementing these advanced features:

1. **Network Namespaces**: Isolate network interfaces and routing tables
2. **User Namespaces**: Map user IDs between host and container
3. **Union Filesystems**: Implement copy-on-write layer management
4. **Container Orchestration**: Build a simple container scheduler
5. **Security Profiles**: Add seccomp or AppArmor restrictions

These features build on the foundation you've learned to create production-ready container systems.
""" 