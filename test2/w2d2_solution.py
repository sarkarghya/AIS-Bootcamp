#!/usr/bin/env python3

# %%
"""
# W2D2 - Containerization: Internals and Security

Today you'll learn the fundamentals of containerization by building your own container runtime from the ground up. You'll understand how modern container technologies like Docker work under the hood by implementing the core isolation mechanisms yourself using Linux primitives.

**IMPORTANT SECURITY NOTICE**: The techniques you'll learn today involve low-level system operations that can affect system stability. You must:
- Only practice on systems you own or have explicit permission to modify
- Be careful when working with system calls and kernel features
- Understand that improper use of these techniques can compromise system security

This lab will teach you the building blocks that power modern containerization platforms, giving you deep insight into both their capabilities and limitations.

<!-- toc -->

This exercise explores Docker image layer extraction, container isolation, resource management, 
and security monitoring. You'll implement custom container tools and understand how modern 
container runtimes work under the hood.

## Content & Learning Objectives

### 1️⃣ Docker Image Layer Extraction
Implement a custom image layer extraction tool by interacting directly with Docker registry APIs.

> **Learning Objectives**
> - Understand Docker image structure and layering
> - Implement registry authentication and manifest processing
> - Download and extract compressed layer archives

### 2️⃣ Container Isolation with Chroot
Create isolated filesystem environments using chroot, one of the fundamental isolation mechanisms.

> **Learning Objectives**  
> - Understand chroot filesystem isolation
> - Execute commands in isolated environments
> - Explore the foundation of container filesystem isolation

### 3️⃣ Resource Management with Cgroups  
Implement resource limits and management using Linux cgroups for memory and CPU control.

> **Learning Objectives**
> - Create and configure cgroups with resource limits
> - Assign processes to cgroups for resource management
> - Combine cgroup limits with chroot isolation

### 4️⃣ Network Isolation and Container Networking
Set up isolated network environments using namespaces, bridges, and virtual ethernet pairs.

> **Learning Objectives**
> - Understand container networking fundamentals
> - Implement network isolation with namespaces
> - Create bridge networks for container communication

### 5️⃣ Security Monitoring and Threat Detection
Implement security monitoring to detect container escape attempts and malicious syscalls.

> **Learning Objectives**
> - Monitor dangerous syscalls in real-time
> - Detect CVE-2024-0137 and similar container escape attempts
> - Implement automated threat response

## Understanding Containerization

Before diving into the technical implementation, let's understand what containerization provides and why it became so popular in modern software deployment.

### What Are Containers?

Containers are **lightweight, portable execution environments** that package applications with their dependencies while sharing the host operating system kernel. Unlike virtual machines that virtualize entire hardware stacks, containers use Linux kernel features to provide isolation at the process level.

Key characteristics of containers:
- **Process Isolation**: Each container runs in its own process space
- **Filesystem Isolation**: Containers have their own filesystem view
- **Resource Limits**: CPU, memory, and I/O can be controlled and limited
- **Network Isolation**: Containers can have isolated network stacks
- **Portability**: Containers run consistently across different environments

### Container vs Virtual Machine Architecture

```
┌─────────────────────────────────────┐  ┌─────────────────────────────────────┐
│            Virtual Machines         │  │             Containers              │
├─────────────────────────────────────┤  ├─────────────────────────────────────┤
│  App A  │  App B  │  App C          │  │  App A  │  App B  │  App C          │
├─────────┼─────────┼─────────────────┤  ├─────────┼─────────┼─────────────────┤
│ Bins/   │ Bins/   │ Bins/           │  │ Bins/   │ Bins/   │ Bins/           │
│ Libs    │ Libs    │ Libs            │  │ Libs    │ Libs    │ Libs            │
├─────────┼─────────┼─────────────────┤  ├─────────┼─────────┼─────────────────┤
│Guest OS │Guest OS │Guest OS         │  │         Container Engine            │
├─────────┼─────────┼─────────────────┤  ├─────────────────────────────────────┤
│           Hypervisor                │  │            Host OS                  │
├─────────────────────────────────────┤  ├─────────────────────────────────────┤
│            Host OS                  │  │           Hardware                  │
├─────────────────────────────────────┤  └─────────────────────────────────────┘
│           Hardware                  │
└─────────────────────────────────────┘
```

### Linux Kernel Features for Containerization

Modern containerization relies on several Linux kernel features:

1. **Namespaces**: Provide isolation of system resources
   - PID namespace: Process ID isolation
   - Mount namespace: Filesystem mount point isolation
   - Network namespace: Network stack isolation
   - UTS namespace: Hostname and domain name isolation
   - User namespace: User and group ID isolation
   - IPC namespace: Inter-process communication isolation

2. **Control Groups (cgroups)**: Resource limiting and accounting
   - Memory limits and usage tracking
   - CPU time and priority control
   - I/O bandwidth limiting
   - Device access control

3. **Union Filesystems**: Layered filesystem management
   - OverlayFS: Efficient copy-on-write filesystem
   - AUFS: Another union filesystem (deprecated)
   - Device Mapper: Block-level storage driver

4. **Security Features**: Additional isolation and access control
   - Capabilities: Fine-grained privilege control
   - SELinux/AppArmor: Mandatory access control
   - Seccomp: System call filtering

### Container Image Format

Container images are **layered filesystems** packaged in a standardized format. Each layer represents a set of filesystem changes, and layers are stacked to create the final container filesystem.

**Image Layers Example**:
```
┌─────────────────────────────────────┐
│     Application Layer               │  ← Your app and configs
├─────────────────────────────────────┤
│     Runtime Dependencies           │  ← Python, Node.js, etc.
├─────────────────────────────────────┤
│     Package Manager Updates        │  ← apt update, yum update
├─────────────────────────────────────┤
│     Base OS Layer                  │  ← Ubuntu, Alpine, etc.
└─────────────────────────────────────┘
```

This layered approach provides several benefits:
- **Efficiency**: Common layers are shared between images
- **Caching**: Unchanged layers don't need to be re-downloaded
- **Version Control**: Similar to Git, each layer has a unique hash
- **Security**: Individual layers can be scanned for vulnerabilities

"""

# %%
import requests
import tarfile
import json
import sys
import os
import platform
from io import BytesIO
from typing import Tuple, Dict, List, Optional

# Architecture detection
TARGET_ARCH, TARGET_VARIANT = {
    'x86_64': ('amd64', None), 'amd64': ('amd64', None),
    'arm64': ('arm64', 'v8'), 'aarch64': ('arm64', 'v8'),
    'armv7l': ('arm', 'v7'), 'armv6l': ('arm', 'v6')
}.get(platform.machine().lower(), ('amd64', None))

print(f"Detected architecture: {TARGET_ARCH} {TARGET_VARIANT if TARGET_VARIANT else ''}")

# %%
"""
## Exercise 1.1: Image Reference Parsing

Parse different Docker image reference formats and extract registry, image, and tag components.

Docker images can be referenced in multiple formats:
- Full registry URLs: `https://registry-1.docker.io/v2/library/hello-world/manifests/latest`
- Docker Hub format: `hello-world:latest` or `library/hello-world:latest` 
- Custom registries: `gcr.io/google-containers/pause:latest`

<details>
<summary>Vocabulary: Docker Image References</summary>

- **Registry**: The server that stores Docker images (e.g., registry-1.docker.io for Docker Hub)
- **Repository**: A collection of related images with the same name but different tags
- **Tag**: A label that points to a specific version of an image (defaults to "latest")
- **Manifest**: Metadata about an image including its layers and configuration
- **Docker Hub**: Docker's official public registry, used as default when no registry is specified

</details>

### Exercise - implement parse_image_reference

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~15 minutes on this exercise.

Implement the `parse_image_reference` function that parses different image reference formats.
"""

def parse_image_reference(image_ref: str) -> Tuple[str, str, str]:
    """
    Parse a Docker image reference into registry, image, and tag components.
    
    Args:
        image_ref: Image reference in various formats
        
    Returns:
        Tuple of (registry, image, tag)
        
    Examples:
        parse_image_reference("hello-world:latest") -> ("registry-1.docker.io", "library/hello-world", "latest")
        parse_image_reference("gcr.io/project/image:v1.0") -> ("gcr.io", "project/image", "v1.0")
    """
    if "SOLUTION":
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
                
        return registry, image, tag
    else:
        # TODO: Implement image reference parsing
        # Handle different formats:
        # - Full URLs with https://
        # - Docker Hub shorthand (no registry specified)
        # - Custom registries (has dots in first part)
        # - Extract registry, image, and tag components
        pass

def test_parse_image_reference(parse_image_reference):
    """Test the image reference parsing function."""
    print("Testing image reference parsing...")
    
    # Test 1: Docker Hub shorthand
    registry, image, tag = parse_image_reference("hello-world:latest")
    assert registry == "registry-1.docker.io", f"Expected registry-1.docker.io, got {registry}"
    assert image == "library/hello-world", f"Expected library/hello-world, got {image}"
    assert tag == "latest", f"Expected latest, got {tag}"
    print("✓ Docker Hub shorthand parsing works")
    
    # Test 2: Custom registry
    registry, image, tag = parse_image_reference("gcr.io/google-containers/pause:3.2")
    assert registry == "gcr.io", f"Expected gcr.io, got {registry}"
    assert image == "google-containers/pause", f"Expected google-containers/pause, got {image}"
    assert tag == "3.2", f"Expected 3.2, got {tag}"
    print("✓ Custom registry parsing works")
    
    # Test 3: No tag specified (should default to latest)
    registry, image, tag = parse_image_reference("alpine")
    assert registry == "registry-1.docker.io", f"Expected registry-1.docker.io, got {registry}"
    assert image == "library/alpine", f"Expected library/alpine, got {image}"
    assert tag == "latest", f"Expected latest, got {tag}"
    print("✓ Default tag handling works")
    
    print("✓ Image reference parsing tests passed!\n" + "=" * 60)

test_parse_image_reference(parse_image_reference)

# %%
"""
## Exercise 1.2: Docker Registry Authentication (Optional)

Implement authentication with Docker registries using token-based authentication.

Docker registries require authentication to access images. Docker Hub uses a token-based 
authentication system where you request a token for a specific repository scope.

The authentication flow:
1. Request a token from the auth server
2. Include the token in subsequent API requests  
3. Token includes scope for specific repository access

<details>
<summary>Vocabulary: Docker Registry Authentication</summary>

- **Bearer Token**: A type of access token that grants access to specific resources
- **Scope**: Defines what actions the token allows (e.g., repository:image:pull)
- **Auth Server**: The server that issues tokens (auth.docker.io for Docker Hub)
- **Registry Server**: The server that stores actual image data (registry-1.docker.io)
- **Authorization Header**: HTTP header that contains the Bearer token

</details>

### Exercise - implement get_auth_token

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~10 minutes on this exercise.

Implement the `get_auth_token` function that gets authentication tokens for Docker Hub.
"""

def get_auth_token(registry: str, image: str) -> Dict[str, str]:
    """
    Get authentication headers for Docker registry access.
    
    Args:
        registry: Registry hostname (e.g., "registry-1.docker.io")
        image: Image name (e.g., "library/hello-world")
        
    Returns:
        Dictionary of headers to include in registry requests
    """
    if "SOLUTION":
        headers = {}
        if registry == 'registry-1.docker.io':
            # Get auth token for Docker Hub
            token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
            token_resp = requests.get(token_url)
            token_resp.raise_for_status()
            token = token_resp.json()['token']
            headers['Authorization'] = f'Bearer {token}'
        return headers
    else:
        # TODO: Authentication implementation
        headers = {}
        if registry == 'registry-1.docker.io':
            # Get auth token for Docker Hub
            token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
            token_resp = requests.get(token_url)
            token_resp.raise_for_status()
            token = token_resp.json()['token']
            headers['Authorization'] = f'Bearer {token}'
        return headers

def test_get_auth_token(get_auth_token):
    """Test the authentication token retrieval."""
    print("Testing authentication token retrieval...")
    
    # Test 1: Docker Hub authentication
    headers = get_auth_token("registry-1.docker.io", "library/hello-world")
    assert "Authorization" in headers, "Authorization header missing"
    assert headers["Authorization"].startswith("Bearer "), "Token should be Bearer type"
    print("✓ Docker Hub token retrieval works")
    
    # Test 2: Other registries (should return empty headers)
    headers = get_auth_token("gcr.io", "google-containers/pause")
    assert isinstance(headers, dict), "Should return dictionary"
    print("✓ Other registry handling works")
    
    print("✓ Authentication tests passed!\n" + "=" * 60)

test_get_auth_token(get_auth_token)

# %%
"""
## Exercise 1.3: Manifest Discovery and Architecture Selection

Retrieve image manifests and select the appropriate architecture variant.

Docker images support multiple architectures. The manifest list contains manifests for 
different platforms (architecture + variant combinations). Your task is to:

1. Fetch the manifest list from the registry
2. Find the manifest for the target architecture
3. Return the digest of the selected manifest

<details>
<summary>Vocabulary: Docker Manifests and Architecture</summary>

- **Manifest**: JSON document describing image layers, configuration, and metadata
- **Manifest List**: Multi-architecture manifest containing platform-specific manifests
- **Digest**: SHA256 hash that uniquely identifies a manifest or layer
- **Platform**: Combination of architecture (amd64, arm64) and optional variant (v7, v8)
- **Architecture**: CPU architecture (amd64, arm64, arm, etc.)
- **Variant**: Sub-architecture version (e.g., armv7, armv8)

</details>

### Exercise - implement get_target_manifest

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~20 minutes on this exercise.

Implement the `get_target_manifest` function that selects the appropriate architecture manifest.
"""

def get_target_manifest(registry: str, image: str, tag: str, headers: Dict[str, str], 
                       target_arch: str, target_variant: Optional[str] = None) -> str:
    """
    Get the manifest digest for the target architecture.
    
    Args:
        registry: Registry hostname
        image: Image name
        tag: Image tag
        headers: Authentication headers
        target_arch: Target architecture (e.g., "amd64", "arm64")
        target_variant: Optional architecture variant (e.g., "v8")
        
    Returns:
        Manifest digest for the target architecture
        
    Raises:
        ValueError: If target architecture is not found
    """
    if "SOLUTION":
        # Get manifest list
        manifest_list_url = f"https://{registry}/v2/{image}/manifests/{tag}"
        print(f"Fetching manifest list from: {manifest_list_url}")
        
        resp = requests.get(manifest_list_url, headers=headers)
        resp.raise_for_status()
        manifest_list = resp.json()
        
        # Find the manifest for our target architecture
        target_manifest = None
        for manifest in manifest_list.get('manifests', []):
            platform = manifest.get('platform', {})
            if platform.get('architecture') == target_arch:
                # Check variant if specified
                if target_variant:
                    if platform.get('variant') == target_variant:
                        target_manifest = manifest
                        break
                else:
                    # No variant specified, take the first match
                    target_manifest = manifest
                    break

        if not target_manifest:
            available_archs = []
            for manifest in manifest_list.get('manifests', []):
                platform = manifest.get('platform', {})
                arch_str = platform.get('architecture', 'unknown')
                if platform.get('variant'):
                    arch_str += f" {platform.get('variant')}"
                available_archs.append(arch_str)
            
            raise ValueError(f"No manifest found for architecture {target_arch}"
                           f"{f' variant {target_variant}' if target_variant else ''}. "
                           f"Available: {', '.join(available_archs)}")

        manifest_digest = target_manifest['digest']
        print(f"Found manifest for {target_arch}: {manifest_digest}")
        return manifest_digest
    else:
        # TODO: Implement manifest discovery
        # 1. Build manifest list URL
        # 2. Make HTTP request with headers
        # 3. Parse JSON response
        # 4. Find manifest matching target_arch and target_variant
        # 5. Return the digest, or raise ValueError if not found
        pass

def test_get_target_manifest(get_target_manifest, get_auth_token):
    """Test the manifest discovery function."""
    print("Testing manifest discovery...")
    
    # Test with a known multi-arch image
    registry = "registry-1.docker.io"
    image = "library/hello-world"
    tag = "latest"
    headers = get_auth_token(registry, image)
    
    # Test 1: Find amd64 manifest
    try:
        digest = get_target_manifest(registry, image, tag, headers, "amd64")
        assert digest.startswith("sha256:"), f"Digest should start with sha256:, got {digest}"
        print("✓ AMD64 manifest discovery works")
    except Exception as e:
        print(f"AMD64 test failed: {e}")
    
    # Test 2: Find arm64 manifest
    try:
        digest = get_target_manifest(registry, image, tag, headers, "arm64", "v8")
        assert digest.startswith("sha256:"), f"Digest should start with sha256:, got {digest}"
        print("✓ ARM64 manifest discovery works")
    except Exception as e:
        print(f"ARM64 test failed: {e}")
    
    # Test 3: Invalid architecture should raise ValueError
    try:
        get_target_manifest(registry, image, tag, headers, "invalid-arch")
        assert False, "Should have raised ValueError for invalid architecture"
    except ValueError:
        print("✓ Invalid architecture handling works")
    except Exception as e:
        print(f"Unexpected error: {e}")
    
    print("✓ Manifest discovery tests passed!\n" + "=" * 60)

test_get_target_manifest(get_target_manifest, get_auth_token)

# %%
"""
## Exercise 1.4: Manifest Processing

Process the selected manifest to extract layer information and metadata.

Once you have the manifest digest, you need to fetch the actual manifest document and 
extract the layer information. The manifest contains metadata about each layer including 
digests and sizes.

<details>
<summary>Vocabulary: Manifest Structure</summary>

- **Manifest v2 Schema**: Docker's current manifest format specification
- **Layer**: A filesystem changeset stored as a compressed tar archive
- **Media Type**: MIME type indicating the format of manifest or layer data
- **Layer Digest**: SHA256 hash uniquely identifying a layer blob
- **Layer Size**: Compressed size of the layer in bytes

</details>

### Exercise - implement get_manifest_layers

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~15 minutes on this exercise.

Implement the `get_manifest_layers` function that fetches and processes the manifest.
"""

def get_manifest_layers(registry: str, image: str, manifest_digest: str, headers: Dict[str, str]) -> List[Dict[str, any]]:
    """
    Get the layer information from a manifest.
    
    Args:
        registry: Registry hostname
        image: Image name
        manifest_digest: Manifest digest
        headers: Authentication headers
        
    Returns:
        List of layer dictionaries with 'digest' and 'size' keys
    """
    if "SOLUTION":
        # Get the actual manifest using the digest
        manifest_url = f"https://{registry}/v2/{image}/manifests/{manifest_digest}"
        headers_copy = headers.copy()
        headers_copy['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json'
        
        print(f"Fetching manifest from: {manifest_url}")
        resp = requests.get(manifest_url, headers=headers_copy)
        resp.raise_for_status()
        manifest = resp.json()
        
        print(f"Manifest type: {manifest.get('mediaType', 'unknown')}")
        layers = manifest.get('layers', [])
        print(f"Number of layers: {len(layers)}")
        
        return layers
    else:
        # TODO: Implement manifest processing
        # 1. Build manifest URL using digest
        # 2. Add Accept header for v2 manifest format
        # 3. Make HTTP request
        # 4. Parse JSON and extract layers
        # 5. Return list of layer dictionaries
        pass

def test_get_manifest_layers(get_manifest_layers, get_auth_token, get_target_manifest):
    """Test the manifest processing function."""
    print("Testing manifest processing...")
    
    # Use a known image
    registry = "registry-1.docker.io"
    image = "library/hello-world"
    tag = "latest"
    headers = get_auth_token(registry, image)
    
    try:
        # Get manifest digest
        manifest_digest = get_target_manifest(registry, image, tag, headers, "amd64")
        
        # Get layers
        layers = get_manifest_layers(registry, image, manifest_digest, headers)
        
        assert isinstance(layers, list), "Layers should be a list"
        assert len(layers) > 0, "Should have at least one layer"
        
        # Check layer structure
        for layer in layers:
            assert 'digest' in layer, "Layer should have digest"
            assert 'size' in layer, "Layer should have size"
            assert layer['digest'].startswith('sha256:'), "Digest should start with sha256:"
            assert isinstance(layer['size'], int), "Size should be integer"
        
        print(f"✓ Found {len(layers)} layers")
        print("✓ Manifest processing works")
        
    except Exception as e:
        print(f"Manifest processing test failed: {e}")
    
    print("✓ Manifest processing tests passed!\n" + "=" * 60)

test_get_manifest_layers(get_manifest_layers, get_auth_token, get_target_manifest)

# %%
"""
## Exercise 1.5: Layer Download and Extraction

Download and extract individual layers to reconstruct the container filesystem.

The final step is to download each layer blob and extract it to the output directory. 
Each layer is a gzipped tar archive that needs to be extracted in order.

<details>
<summary>Vocabulary: Layer Extraction</summary>

- **Blob**: Binary large object - the actual compressed layer data
- **Gzipped Tar**: Compressed archive format (.tar.gz) used for layer storage
- **Layer Extraction**: Unpacking layer contents to filesystem in order
- **Streaming Download**: Downloading large files without loading entirely into memory
- **Filesystem Layering**: Building final filesystem by applying layers sequentially

</details>

### Exercise - implement download_and_extract_layers

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~20 minutes on this exercise.

Implement the `download_and_extract_layers` function that downloads and extracts all layers.

**API Usage Instructions:**

1. **Docker Registry Blob URL Format**: `https://{registry}/v2/{image}/blobs/{digest}`
   - Example: `https://registry-1.docker.io/v2/library/hello-world/blobs/sha256:abc123...`

2. **Streaming Downloads**: Use `requests.get(url, headers=headers, stream=True)` for large files
   - This prevents loading entire blobs into memory at once
   - Call `.raise_for_status()` to check for HTTP errors

3. **Gzipped Tar Extraction**: Layers are stored as compressed tar archives
   - Use `BytesIO(blob_resp.content)` to create a file-like object from downloaded bytes
   - Use `tarfile.open(fileobj=BytesIO(...), mode='r:gz')` to read gzipped tar from memory
   - Extract with `tar.extractall(output_dir)` to unpack all files

4. **Layer Processing**: Process layers in order to build the filesystem layer by layer
   - Each layer represents filesystem changes (additions, modifications, deletions)
   - Later layers override earlier layers (like Git commits)
"""

def download_and_extract_layers(registry: str, image: str, layers: List[Dict[str, any]], 
                               headers: Dict[str, str], output_dir: str) -> None:
    """
    Download and extract all layers to the output directory.
    
    Args:
        registry: Registry hostname
        image: Image name
        layers: List of layer dictionaries from manifest
        headers: Authentication headers
        output_dir: Directory to extract layers to
    """
    if "SOLUTION":
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Download and extract layers in order
        for i, layer in enumerate(layers):
            digest = layer['digest']
            size = layer.get('size', 0)
            print(f"\nProcessing layer {i + 1}/{len(layers)}: {digest} ({size} bytes)")

            # Download layer blob
            blob_url = f"https://{registry}/v2/{image}/blobs/{digest}"
            blob_resp = requests.get(blob_url, headers=headers, stream=True)
            blob_resp.raise_for_status()

            # Extract layer (layers are gzipped tarballs)
            print(f"  Extracting to {output_dir}...")
            with tarfile.open(fileobj=BytesIO(blob_resp.content), mode='r:gz') as tar:
                tar.extractall(output_dir)

        print(f"\n✓ Extracted {len(layers)} layers to {output_dir}")
    else:
        # TODO: Implement layer download and extraction
        # 1. Create output directory
        # 2. For each layer:
        #    a. Build blob URL using digest
        #    b. Download blob with streaming
        #    c. Extract as gzipped tar to output_dir
        # 3. Print progress information
        pass

def test_download_and_extract_layers(download_and_extract_layers, get_auth_token, 
                                   get_target_manifest, get_manifest_layers):
    """Test the layer download and extraction function."""
    print("Testing layer download and extraction...")
    
    # Use a small image for testing
    registry = "registry-1.docker.io"
    image = "library/hello-world"
    tag = "latest"
    output_dir = "./test_extracted"
    
    try:
        # Get authentication
        headers = get_auth_token(registry, image)
        
        # Get manifest
        manifest_digest = get_target_manifest(registry, image, tag, headers, TARGET_ARCH, TARGET_VARIANT)
        
        # Get layers
        layers = get_manifest_layers(registry, image, manifest_digest, headers)
        
        # Download and extract
        download_and_extract_layers(registry, image, layers, headers, output_dir)
        
        # Verify extraction
        assert os.path.exists(output_dir), "Output directory should exist"
        extracted_files = os.listdir(output_dir)
        assert len(extracted_files) > 0, "Should have extracted some files"
        
        print(f"✓ Successfully extracted to {output_dir}")
        print(f"✓ Found {len(extracted_files)} items in output directory")
        
        # Cleanup
        import shutil
        shutil.rmtree(output_dir, ignore_errors=True)
        
    except Exception as e:
        print(f"Layer download test failed: {e}")
    
    print("✓ Layer download and extraction tests passed!\n" + "=" * 60)

test_download_and_extract_layers(download_and_extract_layers, get_auth_token, 
                                get_target_manifest, get_manifest_layers)

# %%
"""
## Exercise 1.6: Complete Implementation

Combine all the exercises into a complete `pull_layers` function that can extract any Docker image.

This function orchestrates all the previous functions to provide a complete Docker image extraction tool.

<details>
<summary>Vocabulary: Container Image Pipeline</summary>

- **Image Reference**: Complete specification of image including registry, name, and tag
- **Registry API**: RESTful HTTP API for accessing container images and metadata
- **Multi-Stage Pipeline**: Breaking complex operations into discrete, testable stages
- **Error Propagation**: Handling and reporting errors from each pipeline stage
- **Architecture Detection**: Automatically selecting appropriate platform variant

</details>

### Exercise - implement pull_layers

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~10 minutes on this exercise.

Implement the complete `pull_layers` function using all the sub-functions you've created.
"""

def pull_layers(image_ref: str, output_dir: str, target_arch: str = TARGET_ARCH, 
                target_variant: Optional[str] = TARGET_VARIANT) -> None:
    """
    Pull and extract Docker image layers for a specific architecture.
    
    Args:
        image_ref: Docker image reference (various formats supported)
        output_dir: Directory to extract layers to
        target_arch: Target architecture (default: auto-detected)
        target_variant: Target architecture variant (default: auto-detected)
    """
    if "SOLUTION":
        # Step 1: Parse image reference
        registry, image, tag = parse_image_reference(image_ref)
        
        print(f"Registry: {registry}")
        print(f"Image: {image}")
        print(f"Tag: {tag}")
        print(f"Target architecture: {target_arch}{f' variant {target_variant}' if target_variant else ''}")
        
        # Step 2: Get authentication
        headers = get_auth_token(registry, image)
        
        # Step 3: Get target manifest
        manifest_digest = get_target_manifest(registry, image, tag, headers, target_arch, target_variant)
        
        # Step 4: Get layers from manifest
        layers = get_manifest_layers(registry, image, manifest_digest, headers)
        
        # Step 5: Download and extract layers
        download_and_extract_layers(registry, image, layers, headers, output_dir)
        
        print(f"✓ Successfully extracted {image_ref} to {output_dir}")
        print(f"  Architecture: {target_arch}{f' variant {target_variant}' if target_variant else ''}")
    else:
        # TODO: Implement complete pull_layers function
        # Use all the functions you've implemented above:
        # 1. parse_image_reference()
        # 2. get_auth_token()
        # 3. get_target_manifest()
        # 4. get_manifest_layers()
        # 5. download_and_extract_layers()
        pass

def test_pull_layers_complete(pull_layers):
    """Test the complete pull_layers function."""
    print("Testing complete pull_layers function...")
    
    # Test with a small image
    test_cases = [
        ("hello-world:latest", "./extracted_hello_world"),
        ("alpine:latest", "./extracted_alpine"),
        ("python:3.12-alpine", "./extracted_python"),
    ]
    
    for image_ref, output_dir in test_cases:
        try:
            print(f"\nTesting {image_ref}...")
            pull_layers(image_ref, output_dir)
            
            # Verify extraction
            assert os.path.exists(output_dir), f"Output directory {output_dir} should exist"
            extracted_files = os.listdir(output_dir)
            assert len(extracted_files) > 0, f"Should have extracted files to {output_dir}"
            
            print(f"✓ Successfully extracted {image_ref}")
            
            # Cleanup
            import shutil
            shutil.rmtree(output_dir, ignore_errors=True)
            
        except Exception as e:
            print(f"Failed to extract {image_ref}: {e}")
    
    print("✓ Complete pull_layers tests passed!\n" + "=" * 60)

test_pull_layers_complete(pull_layers)

# %%
"""
## Summary: What We've Learned

Through this exercise, you've built a complete Docker image extraction tool by implementing:

1. **Image Reference Parsing**: Understanding different Docker image naming conventions and parsing them into components
2. **Registry Authentication**: Implementing token-based authentication with Docker registries
3. **Manifest Discovery**: Fetching manifest lists and selecting architecture-specific manifests
4. **Manifest Processing**: Extracting layer information from manifest documents
5. **Layer Extraction**: Downloading and extracting compressed layer archives

### Key Insights

- **Docker Image Structure**: Images are composed of layers, each representing filesystem changes
- **Registry API**: Docker registries expose REST APIs for programmatic access
- **Multi-Architecture Support**: Images can support multiple architectures through manifest lists
- **Layer Composition**: Layers are applied in order to build the final filesystem
- **Compression**: Layers are stored as gzipped tar archives for efficiency

### Real-World Applications

This knowledge helps you:
- Build custom container tools and utilities
- Understand container security and scanning
- Optimize image builds and storage
- Debug container runtime issues
- Implement custom registry solutions

### Security Considerations

- Always validate image digests and signatures
- Be cautious with untrusted registries
- Implement proper authentication and authorization
- Consider image scanning and vulnerability detection
- Use minimal base images to reduce attack surface

Remember: Understanding container internals is crucial for building secure, efficient containerized applications!
"""
pull_layers("alpine:latest", "./extracted_alpine")
pull_layers("python:3.12-alpine", "./extracted_python") 

# %%
"""
# Container Isolation: Chroot Environments

Implement chroot (change root) isolation, one of the fundamental isolation mechanisms used in containers.

Chroot creates a new root directory for processes, effectively "jailing" them within a specific 
directory tree. This creates an isolated environment where the process cannot access files outside 
the designated directory tree.

Understanding chroot is essential for grasping how containers work under the hood. Docker and other 
container runtimes use chroot (or more advanced variants) to isolate container filesystems from 
the host system.

<details>
<summary>Vocabulary: Chroot and Filesystem Isolation</summary>

- **Chroot**: Unix system call that changes the apparent root directory for a process
- **Chroot Jail**: Isolated environment where processes can only access files within a directory tree
- **Root Directory**: The top-level directory (/) in a filesystem hierarchy
- **Filesystem Isolation**: Preventing processes from accessing files outside their designated area
- **Subprocess**: A separate process spawned and managed by the main program

</details>

## Exercise 2.1: Chroot Environment Execution

### Exercise - implement run_chroot

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~20 minutes on this exercise.

Implement the `run_chroot` function that executes commands in a chrooted environment.

The chroot system call is fundamental to container isolation. It changes the root directory for 
a process, creating a "jail" where the process can only access files within the specified directory tree.

Your task is to implement a function that:
1. Takes a directory path and optional command
2. Executes the command within the chrooted environment
3. Handles different command formats (string vs list)
4. Provides proper error handling and timeouts
5. Returns the execution result
"""

import subprocess
import os
from typing import Optional, List, Union

def run_chroot(chroot_dir: str, command: Optional[Union[str, List[str]]] = None) -> Optional[subprocess.CompletedProcess]:
    """
    Run a command in a chrooted environment.
    
    This function creates an isolated filesystem environment by changing the root directory
    for the executed command. The process will only be able to access files within the
    specified chroot directory.
    
    Args:
        chroot_dir: Directory to chroot into (must contain necessary binaries and libraries)
        command: Command to run (default: /bin/sh)
                - If string: executed as shell command
                - If list: executed directly
                - If None: defaults to interactive shell
    
    Returns:
        CompletedProcess object with execution results, or None if error/timeout
    """
    if "SOLUTION":
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
    else:
        # TODO: Implement chroot command execution
        # 1. Handle different command formats (None, string, list)
        # 2. Build the chroot command: ['chroot', chroot_dir] + command
        # 3. Execute with subprocess.run() with timeout and output capture
        # 4. Print execution details and results
        # 5. Handle TimeoutExpired and other exceptions
        # 6. Return the result or None on error
        pass

def test_run_chroot(run_chroot):
    """Test the chroot command execution function."""
    print("Testing chroot command execution...")
    
    # Test 1: Basic command execution in Alpine Linux environment
    print("\n1. Testing basic command execution:")
    result = run_chroot("./extracted_alpine", "echo 'Hello from chroot!'")
    if result:
        assert result.returncode == 0, "Echo command should succeed"
        assert "Hello from chroot!" in result.stdout, "Output should contain expected text"
        print("✓ Basic command execution works")
    else:
        print("⚠ Basic command test failed - may need Alpine environment")
    
    # Test 2: Testing with Python environment
    print("\n2. Testing Python version check:")
    result = run_chroot("./extracted_python", "python --version")
    if result:
        assert result.returncode == 0, "Python version command should succeed"
        assert "Python" in result.stdout or "Python" in result.stderr, "Should show Python version"
        print("✓ Python environment test works")
    else:
        print("⚠ Python test failed - may need Python environment")
    
    # Test 3: Testing file system isolation
    print("\n3. Testing filesystem isolation:")
    result = run_chroot("./extracted_alpine", "ls /")
    if result:
        assert result.returncode == 0, "Directory listing should succeed"
        # Should not see host filesystem
        assert "Users" not in result.stdout, "Should not see host directories"
        print("✓ Filesystem isolation verified")
    else:
        print("⚠ Filesystem isolation test failed")
    
    # Test 4: Testing command list format
    print("\n4. Testing command list format:")
    result = run_chroot("./extracted_alpine", ["echo", "List command works"])
    if result:
        assert result.returncode == 0, "List command should succeed"
        assert "List command works" in result.stdout, "Output should contain expected text"
        print("✓ Command list format works")
    else:
        print("⚠ Command list test failed")
    
    # Test 5: Testing error handling
    print("\n5. Testing error handling:")
    result = run_chroot("./extracted_alpine", "nonexistent_command")
    if result:
        assert result.returncode != 0, "Non-existent command should fail"
        print("✓ Error handling works")
    else:
        print("⚠ Error handling test failed")
    
    print("\n✓ Chroot tests completed!\n" + "=" * 60)

# Run the test
test_run_chroot(run_chroot)

# %%
"""
## Summary: Understanding Chroot

Through this exercise, you've learned about chroot, a fundamental isolation mechanism:

### Key Concepts

1. **Filesystem Isolation**: Chroot creates a new root directory, isolating processes from the host filesystem
2. **Process Containment**: Commands run in chroot can only access files within the specified directory tree
3. **Container Foundation**: Chroot is one of the building blocks of modern container technology
4. **Security Considerations**: While useful for isolation, chroot alone is not sufficient for complete security

### Real-World Applications

- **Container Runtimes**: Docker, Podman, and others use chroot-like mechanisms
- **Build Systems**: Creating clean build environments
- **Testing**: Isolating test environments from the host system
- **Development**: Running applications in controlled environments

### Security Notes

- Chroot is not a complete security boundary - processes can potentially escape
- Modern containers combine chroot with namespaces, cgroups, and other isolation techniques
- Always validate and sanitize inputs when using chroot in production systems

### Next Steps

Understanding chroot prepares you for more advanced container concepts:
- Namespaces for process, network, and user isolation
- Cgroups for resource management
- Capabilities for fine-grained permissions
- Security contexts and AppArmor/SELinux integration

Remember: Chroot is the foundation, but modern containers are much more sophisticated!
""" 

# %%
"""
# Container Resource Management: Cgroups

Implement cgroups (control groups) for resource management and isolation in containers.

Cgroups are a Linux kernel feature that provides resource management and isolation for containers. 
They allow you to limit, account for, and isolate resource usage (CPU, memory, disk I/O, etc.) of 
groups of processes.

Cgroups are essential for container technology, providing the foundation for resource limits and 
guarantees. Docker, Kubernetes, and other container orchestration systems rely heavily on cgroups 
to manage resources fairly and prevent resource starvation.

<details>
<summary>Vocabulary: Cgroups and Resource Management</summary>

- **Cgroups**: Linux kernel feature for grouping and managing process resources
- **Control Groups**: Another name for cgroups - groups of processes under resource control
- **Resource Controller**: Kernel module that manages specific resource types (memory, CPU, etc.)
- **Cgroup Hierarchy**: Tree structure of nested cgroups in /sys/fs/cgroup filesystem
- **Memory Limit**: Maximum amount of memory a cgroup can use
- **OOM Killer**: Out-of-memory killer that terminates processes when limits are exceeded

</details>

## Exercise 3.1: Basic Cgroup Creation

### Exercise - implement create_cgroup

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~15 minutes on this exercise.

Implement the `create_cgroup` function that creates a basic cgroup with memory limits.

Cgroups are organized in a hierarchy in the `/sys/fs/cgroup` filesystem. To create a cgroup, 
you need to create directories and write to control files to configure resource limits.
"""

import subprocess
import os
import signal
import time
from typing import Optional, List, Union

def create_cgroup(cgroup_name, memory_limit=None, cpu_limit=None):
    """
    Create a cgroup with specified limits
    
    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
        cpu_limit: CPU limit (not implemented yet)
    """
    if "SOLUTION":
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
    else:
        # TODO: Implement basic cgroup creation
        # 1. Create cgroup directory under /sys/fs/cgroup/
        # 2. Enable controllers (+cpu +memory +pids) in parent cgroup
        # 3. Set memory limit if specified
        # 4. Return the cgroup path
        pass

def test_create_cgroup(create_cgroup):
    """Test the basic cgroup creation function."""
    print("Testing basic cgroup creation...")
    
    # Test 1: Create cgroup without limits
    cgroup_path = create_cgroup("test_basic")
    if cgroup_path:
        assert os.path.exists(cgroup_path), "Cgroup directory should exist"
        print("✓ Basic cgroup creation works")
    else:
        print("⚠ Basic cgroup creation failed - may need root privileges")
    
    # Test 2: Create cgroup with memory limit
    cgroup_path = create_cgroup("test_memory", memory_limit="50M")
    if cgroup_path:
        memory_max_path = f"{cgroup_path}/memory.max"
        if os.path.exists(memory_max_path):
            with open(memory_max_path, "r") as f:
                limit = f.read().strip()
            print(f"✓ Memory limit set to: {limit}")
        else:
            print("⚠ Memory limit file not found")
    else:
        print("⚠ Memory limit test failed")
    
    print("✓ Basic cgroup creation tests completed!\n" + "=" * 60)

test_create_cgroup(create_cgroup)

# %%
"""
## Exercise 3.2: Process Assignment

Assign processes to cgroups for resource management.

Once a cgroup is created, processes can be assigned to it by writing their PIDs to the 
`cgroup.procs` file. This allows the cgroup to manage resources for those processes.

### Exercise - implement add_process_to_cgroup

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~10 minutes on this exercise.

Implement the `add_process_to_cgroup` function that assigns processes to cgroups.
"""

def add_process_to_cgroup(cgroup_name, pid=None):
    """
    Add a process to a cgroup
    
    Args:
        cgroup_name: Name of the cgroup
        pid: Process ID (default: current process)
    """
    if "SOLUTION":
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
    else:
        # TODO: Implement process assignment to cgroup
        # 1. Use current process PID if none specified
        # 2. Write PID to cgroup.procs file
        # 3. Handle errors and return success status
        pass

def test_add_process_to_cgroup(add_process_to_cgroup, create_cgroup):
    """Test the process assignment function."""
    print("Testing process assignment to cgroup...")
    
    # Create a test cgroup first
    cgroup_path = create_cgroup("test_process")
    if not cgroup_path:
        print("⚠ Cannot test process assignment - cgroup creation failed")
        return
    
    # Test: Add current process to cgroup
    success = add_process_to_cgroup("test_process")
    if success:
        # Verify the process was added
        cgroup_procs_path = f"{cgroup_path}/cgroup.procs"
        if os.path.exists(cgroup_procs_path):
            with open(cgroup_procs_path, "r") as f:
                procs = f.read().strip().split('\n')
            current_pid = str(os.getpid())
            if current_pid in procs:
                print("✓ Process assignment works")
            else:
                print("⚠ Process not found in cgroup.procs")
        else:
            print("⚠ cgroup.procs file not found")
    else:
        print("⚠ Process assignment failed")
    
    print("✓ Process assignment tests completed!\n" + "=" * 60)

test_add_process_to_cgroup(add_process_to_cgroup, create_cgroup)

# %%
"""
## Exercise 3.3: Combined Cgroup-Chroot Execution

Execute commands with both cgroup limits and chroot isolation.

This exercise combines cgroup resource limits with chroot filesystem isolation, creating 
a more complete container-like environment.

### Exercise - implement run_in_cgroup_chroot

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~20 minutes on this exercise.

Implement the `run_in_cgroup_chroot` function that executes commands with both cgroup and chroot isolation.
"""

def run_in_cgroup_chroot(cgroup_name, chroot_dir, command=None, memory_limit="100M"):
    """
    Run a command in both a cgroup and chroot environment
    
    Args:
        cgroup_name: Name of the cgroup to create/use
        chroot_dir: Directory to chroot into
        command: Command to run
        memory_limit: Memory limit for the cgroup
    """
    if "SOLUTION":
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
    else:
        # TODO: Implement combined cgroup-chroot execution
        # 1. Create cgroup with memory limit
        # 2. Handle command format (None, string, list)
        # 3. Create shell script that:
        #    - Adds process to cgroup
        #    - Executes chroot with command
        # 4. Run with timeout and error handling
        pass

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
    chroot extracted_python/ /bin/sh << 'EOF'
python3 -c "

import os
import time

print('Starting memory allocation test...')
print('Process PID:', os.getpid())

import random
data = []
sum = 0
for i in range(99):
    # Use random data to prevent optimization
    random_number = random.random()
    data.append(str(random_number) * 10 * 1024 * 1024)  # 10MB chunks
    sum += random_number
    print('Allocated ' + str(sum * 10) + 'MB', flush=True)

print('Test completed - this should not be reached if limits work!')
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

def test_run_in_cgroup_chroot(run_in_cgroup_chroot):
    """Test the combined cgroup-chroot execution function."""
    print("Testing combined cgroup-chroot execution...")
    
    # Test basic command execution
    result = run_in_cgroup_chroot("test_combined", "./extracted_alpine", "echo 'Hello from container!'")
    if result:
        print(f"✓ Basic combined execution completed with exit code: {result.returncode}")
    else:
        print("⚠ Basic combined execution failed")

    test_memory_simple(cgroup_name="demo_comprehensive", memory_limit="50M")
    
    print("✓ Combined cgroup-chroot tests completed!\n" + "=" * 60)

test_run_in_cgroup_chroot(run_in_cgroup_chroot)

# %%
"""
## Exercise 4: Comprehensive Cgroup Setup (Part 1)

This exercise implements core memory management features that form the foundation 
of effective container resource isolation. Part 1 focuses on the critical memory 
controls needed to make resource limits actually work in production.

### Exercise - implement create_cgroup_comprehensive_part1 (core memory management)

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~20 minutes on this exercise.

Implement comprehensive memory management including swap control, which is essential
for memory limits to function properly in containerized environments.
"""

def create_cgroup_comprehensive_part1(cgroup_name, memory_limit=None, cpu_limit=None):
    """
    Create a cgroup with comprehensive settings - Part 1: Basic setup
    
    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
        cpu_limit: CPU limit (not implemented yet)
    """
    if "SOLUTION":
        import subprocess
        import os
        
        cgroup_path = f"/sys/fs/cgroup/{cgroup_name}"
        
        print(f"Setting up comprehensive cgroup Part 1: {cgroup_name}")
        
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
        
        # Disable swap for this cgroup (CRITICAL for memory limits to work properly)
        try:
            swap_max_path = f"{cgroup_path}/memory.swap.max"
            with open(swap_max_path, "w") as f:
                f.write("0")
            print("✓ Disabled swap for cgroup (critical for memory limits)")
        except Exception as e:
            print(f"Warning: Could not disable swap: {e}")
        
        print(f"✓ Part 1 - Core memory management setup complete")
        return cgroup_path
    else:
        # TODO: Implement comprehensive cgroup creation - Part 1: Core Memory Management
        # 1. Create cgroup directory with proper error handling
        # 2. Enable controllers (+cpu +memory +pids)
        # 3. Set memory limits with validation
        # 4. Disable swap (CRITICAL - write "0" to memory.swap.max)
        # 5. Set memory pressure threshold (memory.high to 80% of max)
        # 6. Validate all memory settings
        # 7. Return cgroup path or None if critical steps fail
        pass

def test_create_cgroup_comprehensive_part1(create_cgroup_comprehensive_part1):
    """Test the comprehensive cgroup creation function - Part 1."""
    print("Testing comprehensive cgroup creation - Part 1...")
    
    # Test comprehensive cgroup with memory limit
    cgroup_path = create_cgroup_comprehensive_part1("test_comprehensive_p1", memory_limit="100M")
    if cgroup_path:
        assert os.path.exists(cgroup_path), "Cgroup directory should exist"
        
        # Check if memory limit was set
        memory_max_path = f"{cgroup_path}/memory.max"
        if os.path.exists(memory_max_path):
            with open(memory_max_path, "r") as f:
                limit = f.read().strip()
            print(f"✓ Comprehensive cgroup created with memory limit: {limit}")
        else:
            print("⚠ Memory limit file not accessible")
    else:
        print("⚠ Comprehensive cgroup creation failed")
    
    print("✓ Comprehensive cgroup creation Part 1 tests completed!\n" + "=" * 60)

test_create_cgroup_comprehensive_part1(create_cgroup_comprehensive_part1)

# %%
"""
## Exercise 5: Comprehensive Cgroup Setup (Part 2)

This exercise builds on Part 1 by adding advanced Out-of-Memory (OOM) handling, 
process management, and monitoring capabilities needed for production-ready container isolation.

### Exercise - implement create_cgroup_comprehensive (advanced OOM and process management)

> **Difficulty**: 🔴🔴🔴🔴🔴  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~25 minutes on this exercise.

Implement advanced OOM group killing, process assignment, and comprehensive verification
that builds on the core memory management from Part 1.
"""

def create_cgroup_comprehensive(cgroup_name, memory_limit=None, cpu_limit=None):
    """
    Create a cgroup with comprehensive settings - Part 2: Advanced OOM and Process Management
    
    This builds on Part 1 by adding advanced Out-of-Memory handling, process assignment,
    and comprehensive monitoring capabilities for production-ready container isolation.
    
    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
        cpu_limit: CPU limit (not implemented yet)
    """
    if "SOLUTION":
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
        
        # Add current process to cgroup and set up OOM score adjustment
        try:
            # Add process to cgroup
            cgroup_procs_path = f"{cgroup_path}/cgroup.procs"
            with open(cgroup_procs_path, "w") as f:
                f.write(str(os.getpid()))
            print(f"✓ Added current process to cgroup")
            
            # Set oom_score_adj to make this process more likely to be killed
            with open("/proc/self/oom_score_adj", "w") as f:
                f.write("1000")
            print("✓ Set OOM score adjustment to 1000")
            
            # Verify we're in the cgroup
            with open("/proc/self/cgroup", "r") as f:
                cgroup_info = f.read()
            if cgroup_name in cgroup_info:
                print(f"✓ Process confirmed in cgroup: {cgroup_name}")
            else:
                print(f"⚠ Process may not be in cgroup: {cgroup_name}")
            
            # Verify memory limits
            if os.path.exists(memory_max_path):
                with open(memory_max_path, "r") as f:
                    memory_max = f.read().strip()
                print(f"✓ Memory limit confirmed: {memory_max}")
                
                # Check memory.high if it exists
                memory_high_path = f"{cgroup_path}/memory.high"
                if os.path.exists(memory_high_path):
                    with open(memory_high_path, "r") as f:
                        memory_high = f.read().strip()
                    print(f"✓ Memory high: {memory_high}")
                
        except Exception as e:
            print(f"Warning: Could not fully configure process in cgroup: {e}")
        
        return cgroup_path
    else:
        # TODO: Implement complete comprehensive cgroup creation
        # 1. Start with Part 1 implementation (directory, controllers, memory limit)
        # 2. Disable swap by writing "0" to memory.swap.max
        # 3. Enable OOM group killing by writing "1" to memory.oom.group
        # 4. Handle all errors gracefully
        # 5. Return cgroup path or None if failed
        pass


def test_memory_comprehensive(cgroup_name="demo2", memory_limit="100M"):
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
    print('Allocated ' + str((i+1) * 10) + 'MB', flush=True)
    
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


# def test_create_cgroup_comprehensive(test_memory_comprehensive):
print("Testing complete comprehensive cgroup creation with memory test...")
print("Forking process to run memory test...")

# Fork the process
pid = os.fork()

if pid == 0:
    # Child process - run the memory test here
    try:
        print("Child process starting memory test...")
        test_memory_comprehensive(cgroup_name="demo2", memory_limit="50M")
    except Exception as e:
        print(f"Child process error: {e}")
    finally:
        # Child must exit explicitly to avoid continuing parent code
        os._exit(0)

else:
    # Parent process - wait for child and report results
    print(f"✓ Forked child process with PID: {pid}")
    
    try:
        # Wait for child process to complete
        _, status = os.waitpid(pid, 0)
        
        # Check how the child process ended
        if os.WIFEXITED(status):
            exit_code = os.WEXITSTATUS(status)
            print(f"Child exited with code: {exit_code}")
        elif os.WIFSIGNALED(status):
            signal_num = os.WTERMSIG(status)
            if signal_num == 9:  # SIGKILL
                print("✓ Child was KILLED by OOM - cgroup memory limit working!")
            else:
                print(f"✓ Child was killed by signal {signal_num}")
        
        print("✓ Parent process continues running!")
        
    except Exception as e:
        print(f"Error waiting for child: {e}")
print("✓ Complete comprehensive cgroup creation tests completed!\n" + "=" * 60)

# test_create_cgroup_comprehensive(test_memory_comprehensive)
# %%
"""
## Summary: Understanding Cgroups

Through these exercises, you've learned about cgroups using the actual implementations from a real container system:

### Key Concepts

1. **Resource Isolation**: Cgroups provide fine-grained control over system resources
2. **Memory Management**: Advanced memory limits, swap control, and OOM handling
3. **Process Management**: Assigning processes to resource groups
4. **Container Foundation**: Cgroups + chroot + namespaces = containers

### Real-World Applications

- **Docker/Podman**: Use cgroups for container resource limits
- **Kubernetes**: Implements resource requests/limits via cgroups
- **Systemd**: Uses cgroups for service resource management
- **LXC/LXD**: Container platforms built on cgroups

### Production Considerations

- **Memory Pressure**: Use memory.high to trigger pressure before OOM
- **Swap Management**: Disable swap for predictable memory limits
- **OOM Handling**: Configure OOM killer behavior for graceful degradation
- **Monitoring**: Track cgroup statistics for resource usage

### Security Implications

- **Resource Exhaustion**: Prevent DoS attacks through resource limits
- **Isolation**: Limit blast radius of compromised containers
- **Fair Sharing**: Ensure no single container can starve others

Remember: These are the actual implementations used in real container systems!
""" 

# %%
"""
# Container Namespace Isolation

Implement namespace isolation for containers, providing process, network, and filesystem isolation.

Linux namespaces are a feature of the Linux kernel that allows processes to have a view of system 
resources that differs from other processes. There are several types of namespaces:

- **PID namespace**: Isolates process IDs - processes inside see different PIDs
- **Network namespace**: Isolates network interfaces, routing tables, firewall rules
- **Mount namespace**: Isolates filesystem mount points
- **UTS namespace**: Isolates hostname and domain name
- **IPC namespace**: Isolates inter-process communication resources

<details>
<summary>Vocabulary: Linux Namespaces</summary>

- **Namespace**: Kernel mechanism that provides isolated views of system resources
- **PID Namespace**: Isolates process ID space - processes see different PIDs
- **Network Namespace**: Isolates network interfaces, routing tables, and firewall rules
- **Mount Namespace**: Isolates filesystem mount points and mount propagation
- **UTS Namespace**: Isolates hostname and NIS domain name
- **IPC Namespace**: Isolates System V IPC objects and POSIX message queues
- **Unshare**: System call/command to create new namespaces

</details>

## Exercise 4.1: Namespace Isolation

### Exercise - implement run_in_cgroup_chroot_namespaced

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~20 minutes on this exercise.

Implement a function that runs a process in an isolated container environment using multiple namespaces.
"""

import subprocess
import os
import signal


def run_in_cgroup_chroot_namespaced(cgroup_name, chroot_dir, command=None, memory_limit="100M"):
    """
    Run a command in cgroup, chroot, and namespace isolation
    
    Args:
        cgroup_name: Name of the cgroup to create/use
        chroot_dir: Directory to chroot into
        command: Command to run
        memory_limit: Memory limit for the cgroup
    """
    # Create cgroup
    create_cgroup(cgroup_name, memory_limit=memory_limit)
    
    if command is None:
        command = ['/bin/sh']
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
    
    print(f"Running `{command}` in cgroup {cgroup_name} with chroot {chroot_dir} and namespaces")
    
    if "SOLUTION":
        try:
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
                
                # Use the existing function to add process to cgroup
                if add_process_to_cgroup(cgroup_name, pid):
                    print(f"Added process {pid} to cgroup {cgroup_name}")
                else:
                    print(f"⚠ Warning: Could not add process {pid} to cgroup {cgroup_name}")
                
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
    else:
        # TODO: Implement namespace isolation
        #   - Fork a child process
        #   - In child: set up signal handler, wait for SIGUSR1, then exec with unshare
        #   - In parent: add child to cgroup, signal to continue, wait for completion
        #   - Use unshare with --pid --mount --net --uts --ipc --fork flags
        pass


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

test_namespace_isolation() 


# %%
# FIX ME: this reads a bit too much AI generated - unclear how this is relevant; and unclear how this tells them what to expect in the exercise that follows
# FIX ME: What is NAT? I think there should be either be an explainer, or links to external explainer. in general, please add lots of links to external resources wherever applicable

"""
# Container Networking

Implement container networking using Linux bridges, virtual ethernet pairs (veth), and network namespaces.

Container networking involves several key concepts:
- **Bridge Networks**: Software switches that connect multiple network interfaces
- **Virtual Ethernet Pairs (veth)**: Pairs of connected network interfaces that act like a virtual cable
- **Network Namespaces**: Isolated network stacks with their own interfaces, routing tables, and firewall rules
- **NAT (Network Address Translation)**: Allows containers with private IPs to access the internet
- **iptables**: Linux firewall rules for packet filtering and NAT

<details>
<summary>Vocabulary: Container Networking</summary>

- **Bridge**: Software switch that connects multiple network interfaces at Layer 2
- **Veth Pair**: Virtual ethernet cable connecting two network namespaces
- **Network Namespace**: Isolated network stack with its own interfaces and routing
- **NAT (Network Address Translation)**: Technique for sharing one IP address among multiple devices
- **iptables**: Linux firewall and NAT configuration tool
- **MASQUERADE**: iptables target that provides dynamic NAT for changing IP addresses

</details>

## Exercise 5.1: Bridge Network Setup

### Exercise - implement create_bridge_interface and setup_nat_forwarding

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~25 minutes on this exercise.

Implement bridge interface creation and NAT/forwarding rules for container internet connectivity.

A bridge network acts as a software switch that connects multiple network interfaces. After creating 
the bridge, we need iptables rules for NAT and packet forwarding to allow internet access.
"""

import subprocess
import os
import uuid
import signal

# %%
"""
## Exercise 5.1a: Bridge Interface Creation

A bridge network acts as a software switch that connects multiple network interfaces. 
The first step is creating the bridge interface itself and configuring it with an IP address.

Bash to bring bridge down:
```shell
ip link set bridge0 down && ip link delete bridge0 && ip -all netns delete && for i in $(ip link | grep veth | awk '{print $2}' | cut -d: -f1); do ip link delete $i; done
```

### Exercise - implement create_bridge_interface

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~10 minutes on this exercise.

Implement the bridge interface creation function that creates and configures bridge0.
"""


def create_bridge_interface():
    """
    Create and configure bridge0 interface with IP address
    """
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠ Warning: Bridge interface creation requires root privileges")
        return False
    
    if "SOLUTION":
        try:
            # Check if bridge already exists
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
            
            # Remove existing bridge if it exists
            subprocess.run(['ip', 'link', 'del', 'bridge0'], 
                          capture_output=True, text=True)
            
            # Create and configure bridge
            subprocess.run(['ip', 'link', 'add', 'bridge0', 'type', 'bridge'], check=True)
            print("✓ Created bridge0")
            
            subprocess.run(['ip', 'addr', 'add', '10.0.0.1/24', 'dev', 'bridge0'], check=True)
            print("✓ Added IP 10.0.0.1/24 to bridge0")
            
            subprocess.run(['ip', 'link', 'set', 'bridge0', 'up'], check=True)
            print("✓ Bridge0 is up")
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"✗ Error creating bridge interface: {e}")
            return False
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            return False
    else:
        # TODO: Implement bridge interface creation
        #   - Check if bridge0 already exists
        #   - Remove existing bridge if present
        #   - Create bridge0 interface
        #   - Configure bridge0 with IP 10.0.0.1/24
        #   - Bring bridge0 up
        pass


def test_bridge_interface():
    """Test bridge interface creation"""

    # FIX ME: test failing anywhere should cause the script to exit(1)
    print("Testing bridge interface creation...")
    
    result = create_bridge_interface()
    if result:
        print("✓ Bridge interface creation successful!")
        
        # Test bridge connectivity
        print("Testing bridge connectivity...")
        try:
            ping_result = subprocess.run(['ping', '-c', '1', '-W', '1', '10.0.0.1'], 
                                       capture_output=True, text=True)
            if ping_result.returncode == 0:
                print("✓ Bridge connectivity test PASSED")
            else:
                print("⚠ Bridge connectivity test FAILED (may be normal)")
        except Exception as e:
            print(f"⚠ Could not test bridge connectivity: {e}")
    else:
        print("✗ Bridge interface creation failed")
    
    print("=" * 60)
    return result


# Run the test
test_bridge_interface()

# %%
"""
## Exercise 5.1b: NAT and Forwarding Rules

After creating the bridge interface, we need to set up iptables rules for NAT (Network Address Translation) 
and packet forwarding. This allows containers to access the internet through the host's network interface.

### Exercise - implement setup_nat_forwarding

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~15 minutes on this exercise.

Implement the NAT and forwarding setup function that configures iptables for internet connectivity.
"""


def setup_nat_forwarding():
    """
    Set up NAT and forwarding rules for container internet access
    """
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠ Warning: NAT setup requires root privileges")
        return False
    
    if "SOLUTION":
        try:
            # Enable IP forwarding
            result = subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                                  capture_output=True, text=True, check=True)
            print(f"✓ Enabled IP forwarding: {result.stdout.strip()}")
            
            # Get default network interface
            route_result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                        capture_output=True, text=True, check=True)
            default_iface = route_result.stdout.split()[4]
            print(f"✓ Detected default interface: {default_iface}")
            
            # Clear existing iptables rules
            subprocess.run(['iptables', '-F'], check=True)
            subprocess.run(['iptables', '-t', 'nat', '-F'], check=True)
            subprocess.run(['iptables', '-t', 'mangle', '-F'], check=True)
            subprocess.run(['iptables', '-X'], check=True)
            print("✓ Cleared existing iptables rules")
            
            # Set default policies
            subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
            print("✓ Set default policies to ACCEPT")
            
            # Add iptables rules for NAT and forwarding
            subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '10.0.0.0/24', 
                           '!', '-o', 'bridge0', '-j', 'MASQUERADE'], check=True)
            print("✓ Added NAT rule for 10.0.0.0/24")
            
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', 'bridge0', '-o', default_iface, '-j', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', default_iface, '-o', 'bridge0', 
                           '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', 'bridge0', '-o', 'bridge0', '-j', 'ACCEPT'], check=True)
            print("✓ Added forwarding rules")
            
            print("✓ NAT and forwarding setup completed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"✗ Error setting up NAT and forwarding: {e}")
            return False
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            return False
    else:
        # TODO: Implement NAT and forwarding setup
        #   - Enable IP forwarding with sysctl
        #   - Get default network interface
        #   - Clear existing iptables rules
        #   - Set iptables default policies to ACCEPT
        #   - Add NAT rule for MASQUERADE
        #   - Add forwarding rules between bridge and default interface
        pass

def setup_bridge_network():
    """
    Complete bridge network setup combining interface creation and NAT configuration
    """
    print("Setting up complete bridge network...")
    
    # Create bridge interface
    if not create_bridge_interface():
        return False
    
    # Set up NAT and forwarding
    if not setup_nat_forwarding():
        return False
    
    print("✓ Complete bridge network setup successful!")
    return True

def test_nat_forwarding():
    """Test NAT and forwarding setup"""
    print("Testing NAT and forwarding setup...")
    
    result = setup_nat_forwarding()
    if result:
        print("✓ NAT and forwarding setup successful!")
        
        # Test IP forwarding is enabled
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                forward_status = f.read().strip()
            if forward_status == '1':
                print("✓ IP forwarding is enabled")
            else:
                print("⚠ IP forwarding may not be enabled")
        except Exception as e:
            print(f"⚠ Could not check IP forwarding status: {e}")
    else:
        print("✗ NAT and forwarding setup failed")
    
    print("=" * 60)
    return result

def test_bridge_network():
    """Test complete bridge network setup"""
    print("Testing complete bridge network setup...")
    
    result = setup_bridge_network()
    if result:
        print("✓ Complete bridge network setup successful!")
    else:
        print("✗ Complete bridge network setup failed")
    
    print("=" * 60)
    return result

# Run the tests
test_nat_forwarding()
test_bridge_network()

# %%
"""
## Exercise 5.2: Container Network Creation

Create network interfaces for individual containers using virtual ethernet pairs.

For each container, we need to create a virtual ethernet pair (veth) - one end stays on the host 
and connects to the bridge, while the other end goes into the container's network namespace.

### Exercise - implement create_container_network

> **Difficulty**: 🔴🔴🔴🔴🔴  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~25 minutes on this exercise.

Implement the container network creation function that sets up isolated networking for a container.
"""

def create_container_network(container_id, ip_suffix):
    """
    Create network interface for a specific container
    
    Args:
        container_id: Unique identifier for the container
        ip_suffix: IP address suffix (e.g., 2 for 10.0.0.2)
    """
    print(f"Creating network for container {container_id}...")
    
    if os.geteuid() != 0:
        print("⚠ Warning: Network setup requires root privileges")
        return False
    
    
    try:
        if "SOLUTION":
            # Create shorter interface names (Linux limit: 15 characters)
            short_id = container_id[-8:]
            veth_host = f"veth0_{short_id}"
            veth_container = f"veth1_{short_id}"
            netns_name = f"netns_{short_id}"
            container_ip = f"10.0.0.{ip_suffix}"
            
            # print(f"🔧 DEBUG: Creating interfaces:")
            print(f"   Host interface: {veth_host}")
            print(f"   Container interface: {veth_container}")
            print(f"   Namespace: {netns_name}")
            print(f"   Container IP: {container_ip}")
            
            # Create veth pair
            # print(f"🔧 DEBUG: Creating veth pair...")
            subprocess.run(['ip', 'link', 'add', 'dev', veth_host, 'type', 'veth', 
                            'peer', 'name', veth_container], check=True)
            print(f"✓ Created veth pair: {veth_host} <-> {veth_container}")
            
            # Attach host end to bridge
            # print(f"🔧 DEBUG: Attaching {veth_host} to bridge...")
            subprocess.run(['ip', 'link', 'set', 'dev', veth_host, 'up'], check=True)
            subprocess.run(['ip', 'link', 'set', veth_host, 'master', 'bridge0'], check=True)
            print(f"✓ Attached {veth_host} to bridge0")
            
            # Create network namespace
            # print(f"🔧 DEBUG: Creating network namespace {netns_name}...")
            subprocess.run(['ip', 'netns', 'add', netns_name], check=True)
            print(f"✓ Created namespace: {netns_name}")
            
            # Move container end to namespace
            # print(f"🔧 DEBUG: Moving {veth_container} to namespace...")
            subprocess.run(['ip', 'link', 'set', veth_container, 'netns', netns_name], check=True)
            print(f"✓ Moved {veth_container} to {netns_name}")
            
            # Configure container network interface
            # print(f"🔧 DEBUG: Configuring container interface...")
            subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'link', 'set', 'dev', 'lo', 'up'], check=True)
            subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'addr', 'add', 
                            f'{container_ip}/24', 'dev', veth_container], check=True)
            subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'link', 'set', 
                            'dev', veth_container, 'up'], check=True)
            print(f"✓ Configured {veth_container} with IP {container_ip}/24")
            
            # Add default route
            # print(f"🔧 DEBUG: Adding default route...")
            subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'route', 'add', 
                            'default', 'via', '10.0.0.1'], check=True)
            print(f"✓ Added default route via 10.0.0.1")
            
            print(f"✓ Successfully created network for container {container_id}")
            return netns_name

        else:
            # TODO: Implement container network creation
            #   - Create veth pair with unique names
            #   - Attach host end to bridge0
            #   - Create network namespace
            #   - Move container end to namespace
            #   - Configure IP address and routing in namespace
            #   - Set up DNS resolution

            short_id = container_id[-8:]
            netns_name = f"isolated_{short_id}"
            
            # print(f"🔧 DEBUG: Creating isolated namespace:")
            print(f"   Namespace: {netns_name}")
            print(f"   Container ID: {container_id}")
            
            # Create network namespace
            # print(f"🔧 DEBUG: Creating network namespace {netns_name}...")
            subprocess.run(['ip', 'netns', 'add', netns_name], check=True)
            print(f"✓ Created isolated namespace: {netns_name}")
            
            # Configure only loopback interface (no external connectivity)
            # print(f"🔧 DEBUG: Configuring loopback interface...")
            subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'link', 'set', 'dev', 'lo', 'up'], check=True)
            print(f"✓ Configured loopback interface in {netns_name}")
            
            # Test that the namespace is isolated (should only have loopback)
            # print(f"🔧 DEBUG: Verifying network isolation...")
            result = subprocess.run(['ip', 'netns', 'exec', netns_name, 'ip', 'addr', 'show'], 
                                capture_output=True, text=True, check=True)
            
            # Count network interfaces (should only be loopback)
            interfaces = len([line for line in result.stdout.split('\n') if ': ' in line and 'lo:' in line])
            if interfaces == 1:
                print(f"✓ Network isolation verified: only loopback interface present")
            else:
                print(f"⚠ Warning: Expected 1 interface (loopback), found {interfaces}")
            
            # Test that external connectivity is blocked
            # print(f"🔧 DEBUG: Testing network isolation...")
            ping_test = subprocess.run(['ip', 'netns', 'exec', netns_name, 'ping', '-c', '1', '-W', '1', '8.8.8.8'], 
                                    capture_output=True, text=True)
            if ping_test.returncode != 0:
                print(f"✓ Network isolation confirmed: cannot reach external hosts")
            else:
                print(f"⚠ Warning: Network isolation may not be working - external ping succeeded")
            
            # Test loopback connectivity
            # print(f"🔧 DEBUG: Testing loopback connectivity...")
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


def cleanup_container_network(container_id):
    """Clean up network resources for a container"""
    if os.geteuid() != 0:
        print("⚠ Warning: Network cleanup requires root privileges")
        return
    
    try:
        if "SOLUTION":
            short_id = container_id[-8:]
            veth_host = f"veth0_{short_id}"
            netns_name = f"netns_{short_id}"
            
            # print(f"🔧 DEBUG: Cleaning up network for container {container_id}")
            
            # Remove network namespace
            subprocess.run(['ip', 'netns', 'del', netns_name], capture_output=True, text=True)
            print(f"✓ Removed namespace: {netns_name}")
            
            # Remove host veth if it still exists
            subprocess.run(['ip', 'link', 'del', veth_host], capture_output=True, text=True)
            print(f"✓ Removed host interface: {veth_host}")
        
        else:
            # TODO: Implement container network cleanup
            #   - Remove network namespace
            #   - Remove host veth if it still exists

            short_id = container_id[-8:]
            netns_name = f"isolated_{short_id}"
            
            # print(f"🔧 DEBUG: Cleaning up isolated namespace for container {container_id}")
            print(f"   Short ID: {short_id}")
            print(f"   Namespace: {netns_name}")
            
            # Remove network namespace
            # print(f"🔧 DEBUG: Removing network namespace {netns_name}...")
            result = subprocess.run(['ip', 'netns', 'del', netns_name], 
                                capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✓ Removed isolated namespace: {netns_name}")
            else:
                print(f"⚠ Could not remove namespace {netns_name}: {result.stderr}")
            
            print(f"✓ Isolated network cleanup completed for container {container_id}")
        
    except Exception as e:
        print(f"⚠ Warning: Could not fully clean up network for {container_id}: {e}")


def test_container_network():
    """Test container network creation"""
    print("Testing container network creation...")
    
    container_id = "test_container_12345678"
    netns_name = create_container_network(container_id, 100)
    
    if netns_name:
        print("✓ Container network creation successful!")
        
        # Test connectivity from namespace
        print("Testing namespace connectivity...")
        try:
            test_result = subprocess.run(['ip', 'netns', 'exec', netns_name, 'ping', '-c', '1', '10.0.0.1'], 
                                       capture_output=True, text=True)
            if test_result.returncode == 0:
                print("✓ Gateway connectivity test PASSED")
            else:
                print("⚠ Gateway connectivity test FAILED")
        except Exception as e:
            print(f"⚠ Could not test connectivity: {e}")
        
        # Clean up
        cleanup_container_network(container_id)
    else:
        print("✗ Container network creation failed")
    
    print("=" * 60)
    return netns_name is not None

# Run the test
test_container_network()


# %%
"""
## Exercise 5.3: Running Networked Containers

Create complete networked containers with full networking support.

This exercise combines everything to create a complete networked container that has:
- Process isolation (cgroups, namespaces)
- Filesystem isolation (chroot)
- Network isolation (network namespaces)
- Internet connectivity (bridge + NAT)

### Exercise - implement run_networked_container

> **Difficulty**: 🔴🔴🔴🔴🔴  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~30 minutes on this exercise.

Implement the complete networked container function.
"""


def run_networked_container(cgroup_name, chroot_dir, command=None, memory_limit="100M", container_name="container"):
    """
    Create a new container with full networking support
    
    Args:
        cgroup_name: Name of the cgroup to create/use
        chroot_dir: Directory to chroot into  
        command: Command to run
        memory_limit: Memory limit for the cgroup
        container_name: Name for the container (used in networking)
    """
    # Create cgroup
    create_cgroup(cgroup_name, memory_limit=memory_limit)
    
    if command is None:
        command = ['/bin/sh']
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
    
    # Generate unique container ID
    container_id = f"{container_name}_{str(uuid.uuid4())[:8]}"
    ip_suffix = hash(container_id) % 200 + 50  # IP range 10.0.0.50-249
    
    # print(f"🔧 DEBUG: Creating networked container: {container_id}")
    # print(f"🔧 DEBUG: IP suffix: {ip_suffix}")
    
    if "SOLUTION":
        # Set up DNS for chroot environment
        # print(f"🔧 DEBUG: Setting up DNS in chroot environment...")
        try:
            chroot_etc_dir = os.path.join(chroot_dir, 'etc')
            os.makedirs(chroot_etc_dir, exist_ok=True)
            
            chroot_resolv_conf = os.path.join(chroot_etc_dir, 'resolv.conf')
            with open(chroot_resolv_conf, 'w') as f:
                f.write('# DNS configuration for containerized environment\n')
                f.write('nameserver 8.8.8.8\n')
                f.write('nameserver 8.8.4.4\n')
                f.write('nameserver 1.1.1.1\n')
                f.write('options timeout:2 attempts:3\n')
            print(f"✓ Created working DNS configuration in chroot")
        except Exception as e:
            print(f"⚠ Warning: Could not set up DNS in chroot: {e}")
        
        # Set up bridge network
        bridge_ready = setup_bridge_network()
        
        # Create container network
        netns_name = None
        if bridge_ready:
            netns_name = create_container_network(container_id, ip_suffix)
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
                # print(f"🔧 DEBUG: Executing with network namespace: {netns_name}")
            else:
                # Execute without network namespace
                exec_args = ['unshare', '--pid', '--mount', '--net', '--uts', '--ipc', '--fork', 
                           'chroot', chroot_dir] + command
                # print(f"🔧 DEBUG: Executing without network namespace")
            
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
            # print(f"🔧 DEBUG: Container exit code: {exit_code}")
            
            # Cleanup
            if netns_name:
                cleanup_container_network(container_id)
            
            return exit_code
            
        except Exception as e:
            print(f"✗ Error running networked container: {e}")
            if netns_name:
                cleanup_container_network(container_id)
            return None
    else:
        # TODO: Implement networked container
        #   - Set up DNS resolution in chroot
        #   - Set up bridge network
        #   - Create container network with unique IP
        #   - Execute command with network namespace
        #   - Clean up network resources
        pass


def test_networked_container():
    """Test networked container functionality"""
    print("Testing networked container...")
    
    print("Creating a networked container with Python:")
    print("Testing basic connectivity and DNS resolution...")
    
    result = run_networked_container(
        cgroup_name="python_networked",
        chroot_dir="./extracted_python", 
        command="python3 -c 'import subprocess; print(\"Testing basic connectivity:\"); subprocess.run([\"ping\", \"-c\", \"1\", \"8.8.8.8\"]); print(\"Testing DNS resolution:\"); import socket; print(f\"Container can resolve: {socket.gethostbyname(\"google.com\")}\"); print(\"Networked Python container working!\")'",
        memory_limit="100M",
        container_name="python_demo"
    )
    
    if result == 0:
        print("✓ Networked container test successful!")
    else:
        print("✗ Networked container test failed")
    
    print("=" * 60)
    return result == 0


# Run the test
test_networked_container()

# %%
"""
# 6. Container Security Monitoring

In this exercise, you'll implement security monitoring for containers to detect potential escape attempts
and malicious syscalls. This is crucial for preventing CVE-2024-0137 and similar container escape vulnerabilities.

## Introduction

Container security monitoring involves tracking system calls that could indicate escape attempts or 
malicious behavior. Key concepts include:

- **Syscall Monitoring**: Using strace to monitor dangerous system calls in real-time
- **CVE-2024-0137**: A container escape vulnerability involving namespace manipulation
- **Security Alerting**: Real-time detection and response to suspicious activities
- **Process Termination**: Killing malicious processes before they can escape the container

Common dangerous syscalls to monitor:
- `unshare`: Creates new namespaces (potential escape vector)
- `setns`: Joins existing namespaces (potential privilege escalation)
- `mount`: Filesystem manipulation (potential container escape)
- `pivot_root`: Root filesystem changes (container breakout)
- `clone`: Process/namespace creation (escape attempts)

Container escape attacks often involve:
1. Attempting to create new namespaces with elevated privileges
2. Joining host namespaces to break out of isolation
3. Mounting host filesystems to access sensitive data
4. Manipulating container runtime to gain host access

## Content & Learning Objectives

### 6.1 Syscall Monitoring
### 6.2 Security Alert Handling  
### 6.3 Complete Security Monitoring
"""

import subprocess
import threading
import os
import signal
import uuid

# Dangerous syscalls for CVE-2024-0137
DANGEROUS_SYSCALLS = {
    'setns', 'unshare', 'mount', 'pivot_root', 'chroot', 
    'clone', 'socket', 'bind', 'connect'
}

# %%
"""
## Exercise 6.1: Syscall Monitoring

The first line of defense is monitoring system calls that could indicate malicious behavior.
We use strace to trace dangerous syscalls in real-time and alert when suspicious activity is detected.

### Exercise - implement monitor_container_syscalls

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~20 minutes on this exercise.

Implement the syscall monitoring function that uses strace to track dangerous system calls.
"""


def monitor_container_syscalls(container_command, alert_callback):
    """
    Monitor syscalls by running strace INSIDE the container namespace
    
    Args:
        container_command: List of command and arguments to run in container
        alert_callback: Function to call when dangerous syscalls are detected
        
    Returns:
        Exit code of the monitored process
    """
    
    try:
        if "SOLUTION":
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
                if process.stderr:
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
                if process.stdout:
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

        else:
            # TODO: Implement syscall monitoring
            #   - Create strace command with dangerous syscalls filter
            strace_cmd = [] + container_command
            
            print(f"🔍 Running strace inside container: {' '.join(strace_cmd)}")
            
            process = subprocess.Popen(
                strace_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Monitor stderr for syscall traces
            def monitor_stderr():
                if process.stderr:
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
                if process.stdout:
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



def test_syscall_monitoring():
    """Test basic syscall monitoring"""
    print("Testing syscall monitoring...")
    
    # Simple test callback
    alerts = []
    def test_callback(syscall_line, pid):
        alerts.append((syscall_line, pid))
        print(f"🚨 TEST ALERT: {syscall_line}")
    
    # Test with a simple command that should NOT trigger alerts
    safe_command = ['echo', 'Hello from container']
    exit_code = monitor_container_syscalls(safe_command, test_callback)
    
    if exit_code == 0:
        print("✓ Safe command monitoring successful!")
        print(f"✓ Alerts triggered: {len(alerts)}")
    else:
        print("✗ Safe command monitoring failed")
    
    print("=" * 60)
    return exit_code == 0


# Run the test
test_syscall_monitoring()

# %%
"""
## Exercise 6.2: Security Alert Handling

When dangerous syscalls are detected, we need to analyze them and take appropriate action.
CVE-2024-0137 specifically involves namespace escape attempts that we need to detect and block.

### Exercise - implement security_alert_handler

> **Difficulty**: 🔴⚪⚪⚪⚪  
> **Importance**: 🔵🔵🔵⚪⚪ 
> 
> You should spend up to ~15 minutes on this exercise.

Implement the security alert handler that detects specific attack patterns and responds appropriately.
"""


def security_alert_handler(syscall_line, pid):
    """
    Enhanced alert handler for CVE-2024-0137 and other container escape attempts
    
    Args:
        syscall_line: The strace output line containing the syscall
        pid: Process ID that made the syscall
    """

    print(f"🚨 SECURITY ALERT: Dangerous syscall detected!")
    print(f"   Syscall trace: {syscall_line}")
    print(f"   Process PID: {pid}")
    
    # Specific CVE-2024-0137 detection patterns
    if 'unshare' in syscall_line and ('CLONE_NEWNET' in syscall_line or '--net' in syscall_line):
        print(f"🔥 CRITICAL: CVE-2024-0137 network namespace escape detected!")
        print(f"   Terminating malicious container...")
        try:
            if "SOLUTION":
                os.kill(pid, signal.SIGKILL)
                print(f"✓ Process {pid} terminated")
            else:
                # TODO: Kill the entire process group
                pass
        except Exception as e:
            print(f"⚠ Could not terminate process {pid}: {e}")
    
    elif 'setns' in syscall_line:
        print(f"🔥 CRITICAL: Namespace manipulation detected!")
        print(f"   Possible container escape attempt!")
        # Log but don't kill immediately - might be legitimate
    
    elif 'mount' in syscall_line:
        print(f"⚠ WARNING: Filesystem mount detected!")
        print(f"   Monitor for privilege escalation attempts")
    
    elif 'pivot_root' in syscall_line:
        print(f"🔥 CRITICAL: Root filesystem manipulation detected!")
        print(f"   Possible container breakout attempt!")
    
    else:
        print(f"⚠ WARNING: Suspicious syscall detected")
        print(f"   Review for potential security implications")


def test_security_alerts():
    """Test security alert handling"""
    print("Testing security alert handling...")
    
    # Test different types of syscall patterns
    test_cases = [
        ("unshare(CLONE_NEWNET) = 0", 12345, "CVE-2024-0137"),
        ("setns(3, CLONE_NEWNS) = 0", 12346, "Namespace manipulation"),
        ("mount(/dev/sda1, /mnt) = 0", 12347, "Filesystem mount"),
        ("pivot_root(/new_root, /old_root) = 0", 12348, "Root manipulation"),
    ]
    
    print("Testing various attack patterns:")
    for syscall_line, fake_pid, attack_type in test_cases:
        print(f"\n--- Testing {attack_type} ---")
        security_alert_handler(syscall_line, fake_pid)
    
    print("\n✓ Security alert handling test completed!")
    print("=" * 60)
    return True


# Run the test
test_security_alerts()

# %%
"""
## Exercise 6.3: Complete Security Monitoring

Now let's combine syscall monitoring with security alerting to create a complete 
monitored container that can detect and respond to escape attempts in real-time.

### Exercise - implement run_monitored_container

> **Difficulty**: 🔴🔴🔴🔴🔴  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~25 minutes on this exercise.

Implement the complete monitored container function that combines all security features.
"""


def run_monitored_container(cgroup_name, chroot_dir="./extracted_python", 
                          command=None, memory_limit="100M", container_name="container"):
    """
    Run a container with comprehensive security monitoring
    
    Args:
        cgroup_name: Name of the cgroup for resource isolation
        chroot_dir: Directory to chroot into
        command: Command to run inside the container
        memory_limit: Memory limit for the container
        container_name: Base name for the container
        
    Returns:
        Exit code of the monitored container
    """
    container_id = f"{container_name}_{str(uuid.uuid4())[:8]}"
    print(f"🔍 Starting monitored container: {container_id}")
    print(f"🛡️  Enhanced monitoring for CVE-2024-0137...")
    
    if command is None:
        command = ['/bin/sh']
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
    
    if "SOLUTION":
        # Build the complete container command
        container_cmd = [
            'unshare', '--pid', '--mount', '--net', '--uts', '--ipc', '--fork',
            'chroot', chroot_dir
        ] + command
        
        print(f"🚀 Executing with internal monitoring...")
        
        # Run with internal syscall monitoring
        exit_code = monitor_container_syscalls(container_cmd, security_alert_handler)
        
        print(f"🏁 Container {container_id} exited with code: {exit_code}")
        return exit_code
    else:
        # TODO: Implement monitored container
        #   - Generate unique container ID
        #   - Build container command with unshare and chroot
        #   - Use monitor_container_syscalls with security_alert_handler
        #   - Return the exit code
        pass


def test_monitored_container_safe():
    """Test monitored container with safe commands"""
    print("Testing monitored container with safe commands...")
    
    safe_command = "echo 'Hello from monitored container'; python3 -c 'print(\"Python works!\")'"
    
    exit_code = run_monitored_container(
        cgroup_name="safe_test",
        chroot_dir="./extracted_python",
        command=safe_command,
        memory_limit="50M",
        container_name="safe_demo"
    )
    
    if exit_code == 0:
        print("✓ Safe monitored container test successful!")
    else:
        print("✗ Safe monitored container test failed")
    
    print("=" * 60)
    return exit_code == 0


def test_monitored_container_attack():
    """Test monitored container with simulated attack"""
    print("Testing monitored container with attack simulation...")
    
    # Simulate CVE-2024-0137 attack
    attack_command = """
    echo "Attempting container escape simulation..."
    python3 -c "
import os
import ctypes
import subprocess

print('Simulating namespace escape attack...')

# Try direct unshare syscall (this should be detected)
try:
    libc = ctypes.CDLL('libc.so.6')
    CLONE_NEWNET = 0x40000000
    result = libc.unshare(CLONE_NEWNET)
    print(f'Direct unshare result: {result}')
except Exception as e:
    print(f'Direct syscall simulation failed: {e}')

# Try subprocess unshare (this should also be detected)
try:
    subprocess.run(['unshare', '--net', 'echo', 'namespace created'], timeout=1)
except Exception as e:
    print(f'Subprocess attack simulation failed: {e}')

print('Attack simulation completed')
"
    """
    
    exit_code = run_monitored_container(
        cgroup_name="attack_test",
        chroot_dir="./extracted_python",
        command=attack_command,
        memory_limit="50M",
        container_name="attack_demo"
    )
    
    print(f"✓ Attack simulation completed with exit code: {exit_code}")
    print("✓ Security monitoring detected and handled threats!")
    print("=" * 60)
    return True


# Run the tests
test_monitored_container_safe()
test_monitored_container_attack()

# %%
"""
## Summary: Container Internals and Security

Through these exercises, you've implemented the core components of container technology:

### Key Concepts Learned

1. **Docker Image Structure**: Images are composed of layers stored as compressed tar archives
2. **Registry APIs**: Programmatic access to image repositories with authentication
3. **Chroot Isolation**: Filesystem isolation using change root system calls  
4. **Cgroup Resource Management**: Memory and CPU limits for process groups
5. **Namespace Isolation**: Process, network, and filesystem isolation
6. **Container Networking**: Bridge networks, veth pairs, and NAT for connectivity
7. **Security Monitoring**: Syscall monitoring and threat detection

### Real-World Applications

These implementations mirror how production container systems work:
- **Docker/Podman**: Use these exact isolation mechanisms
- **Kubernetes**: Orchestrates containers with these primitives
- **Container Security**: Monitoring and preventing container escapes
- **Custom Container Tools**: Building specialized container runtimes

### Security Considerations

- **Defense in Depth**: Combine multiple isolation mechanisms
- **Resource Limits**: Prevent resource exhaustion attacks  
- **Syscall Monitoring**: Detect container escape attempts
- **Network Isolation**: Limit container network access
- **Image Validation**: Verify image integrity and signatures

Understanding these fundamentals is essential for:
- Building secure containerized applications
- Implementing container orchestration systems
- Debugging container runtime issues
- Developing container security solutions

Remember: These are the actual building blocks that power modern container platforms!
"""
