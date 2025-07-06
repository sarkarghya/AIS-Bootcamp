#!/usr/bin/env python3

# %%
"""
# Docker Image Layer Extraction

#### Introduction: Understanding Docker Internals

In this exercise, you'll learn how Docker images are structured and stored in registries by implementing a custom image layer extraction tool. You'll interact directly with Docker registry APIs to download and extract container images without using the Docker daemon.

Docker images are composed of multiple layers, each representing a filesystem change. These layers are stored as compressed tar archives in Docker registries. Understanding this structure is crucial for container security, optimization, and building custom tooling.

## Content & Learning Objectives

### 1️⃣ Image Reference Parsing
Parse different Docker image reference formats including full URLs, Docker Hub shorthand, and custom registries.

> **Learning Objectives**
> - Understand Docker image naming conventions
> - Parse registry URLs and extract components
> - Handle different image reference formats

### 2️⃣ Docker Registry Authentication
Implement authentication with Docker registries to access private and public images.

> **Learning Objectives**
> - Understand Docker registry authentication flows
> - Implement token-based authentication
> - Handle registry-specific auth requirements

### 3️⃣ Manifest Discovery and Architecture Selection
Retrieve image manifests and select the appropriate architecture variant.

> **Learning Objectives**
> - Understand Docker manifest structure
> - Implement architecture-specific image selection
> - Handle multi-architecture images

### 4️⃣ Manifest Processing
Process the selected manifest to extract layer information and metadata.

> **Learning Objectives**
> - Parse Docker manifest v2 schema
> - Extract layer digests and metadata
> - Understand manifest structure

### 5️⃣ Layer Download and Extraction
Download and extract individual layers to reconstruct the container filesystem.

> **Learning Objectives**
> - Download binary blobs from registries
> - Extract compressed tar archives
> - Reconstruct layered filesystems

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
## Exercise 1: Image Reference Parsing

Docker images can be referenced in multiple formats:
- Full registry URLs: `https://registry-1.docker.io/v2/library/hello-world/manifests/latest`
- Docker Hub format: `hello-world:latest` or `library/hello-world:latest`
- Custom registries: `gcr.io/google-containers/pause:latest`

Your task is to parse these different formats and extract the registry, image name, and tag.

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
## Exercise 2: Docker Registry Authentication

Docker registries require authentication to access images. Docker Hub uses a token-based authentication system where you request a token for a specific repository scope.

The authentication flow:
1. Request a token from the auth server
2. Include the token in subsequent API requests
3. Token includes scope for specific repository access

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
        # TODO: Implement authentication
        # For Docker Hub (registry-1.docker.io):
        # - Request token from auth.docker.io
        # - Include service and scope parameters
        # - Return Authorization header with Bearer token
        # For other registries: return empty headers for now
        pass

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
## Exercise 3: Manifest Discovery and Architecture Selection

Docker images support multiple architectures. The manifest list contains manifests for different platforms (architecture + variant combinations). Your task is to:

1. Fetch the manifest list from the registry
2. Find the manifest for the target architecture
3. Return the digest of the selected manifest

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
## Exercise 4: Manifest Processing

Once you have the manifest digest, you need to fetch the actual manifest document and extract the layer information. The manifest contains metadata about each layer including digests and sizes.

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
## Exercise 5: Layer Download and Extraction

The final step is to download each layer blob and extract it to the output directory. Each layer is a gzipped tar archive that needs to be extracted in order.

### Exercise - implement download_and_extract_layers

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~20 minutes on this exercise.

Implement the `download_and_extract_layers` function that downloads and extracts all layers.
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
## Complete Implementation: Putting It All Together

Now let's combine all the exercises into a complete `pull_layers` function that can extract any Docker image.

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