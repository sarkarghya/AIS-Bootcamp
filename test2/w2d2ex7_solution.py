#!/usr/bin/env python3

import os
import subprocess
import shutil
import uuid
from pathlib import Path

class SimpleContainer:
    def __init__(self, base_path="/tmp/containers"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(exist_ok=True)
        self.images_path = self.base_path / "images"
        self.containers_path = self.base_path / "containers"
        self.images_path.mkdir(exist_ok=True)
        self.containers_path.mkdir(exist_ok=True)

    def check_exists(self, name, container_type="image"):
        """Check if image or container exists"""
        if container_type == "image":
            return (self.images_path / name).exists()
        else:
            return (self.containers_path / name).exists()

    def init_image(self, source_dir, image_name=None):
        """Create initial image from directory"""
        if image_name is None:
            image_name = f"img_{uuid.uuid4().hex[:8]}"
        
        image_path = self.images_path / image_name
        
        if not Path(source_dir).exists():
            print(f"Error: Source directory '{source_dir}' does not exist")
            return None
        
        # Copy source directory to create base image
        shutil.copytree(source_dir, image_path, dirs_exist_ok=True)
        
        # Create metadata
        metadata = {
            "source": str(source_dir),
            "created": str(uuid.uuid4()),
            "type": "base_image"
        }
        
        with open(image_path / ".image_meta", "w") as f:
            for key, value in metadata.items():
                f.write(f"{key}={value}\n")
        
        print(f"Created image: {image_name}")
        return image_name

    def run_container(self, image_name, command=None):
        """Create and run container from image"""
        if not self.check_exists(image_name, "image"):
            print(f"Error: Image '{image_name}' does not exist")
            return None
        
        container_id = f"ps_{uuid.uuid4().hex[:8]}"
        container_path = self.containers_path / container_id
        image_path = self.images_path / image_name
        
        # Create container as copy of image
        shutil.copytree(image_path, container_path, dirs_exist_ok=True)
        
        # Store command metadata
        if command:
            with open(container_path / f"{container_id}.cmd", "w") as f:
                f.write(command)
        
        print(f"Created container: {container_id}")
        return container_id

    def execute_in_container(self, container_id, command):
        """Execute command in container using chroot"""
        if not self.check_exists(container_id, "container"):
            print(f"Error: Container '{container_id}' does not exist")
            return False
        
        container_path = self.containers_path / container_id
        
        try:
            # Use chroot to execute in container
            result = subprocess.run([
                'chroot', str(container_path), 'sh', '-c', command
            ], capture_output=True, text=True, timeout=30)
            
            # Log execution
            log_path = container_path / f"{container_id}.log"
            with open(log_path, "a") as f:
                f.write(f"Command: {command}\n")
                f.write(f"Exit code: {result.returncode}\n")
                f.write(f"Stdout: {result.stdout}\n")
                f.write(f"Stderr: {result.stderr}\n")
                f.write("---\n")
            
            print(f"Executed in {container_id}: {command}")
            print(f"Exit code: {result.returncode}")
            if result.stdout:
                print(f"Output: {result.stdout}")
            if result.stderr:
                print(f"Error: {result.stderr}")
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"Error executing command: {e}")
            return False

    def commit_container(self, container_id, new_image_name):
        """Commit container changes to new image"""
        if not self.check_exists(container_id, "container"):
            print(f"Error: Container '{container_id}' does not exist")
            return False
        
        if self.check_exists(new_image_name, "image"):
            print(f"Removing existing image: {new_image_name}")
            shutil.rmtree(self.images_path / new_image_name)
        
        container_path = self.containers_path / container_id
        new_image_path = self.images_path / new_image_name
        
        # Copy container state to new image
        shutil.copytree(container_path, new_image_path, dirs_exist_ok=True)
        
        # Update metadata
        metadata = {
            "source": f"container_{container_id}",
            "created": str(uuid.uuid4()),
            "type": "committed_image",
            "parent_container": container_id
        }
        
        with open(new_image_path / ".image_meta", "w") as f:
            for key, value in metadata.items():
                f.write(f"{key}={value}\n")
        
        # Clean up container-specific files
        for file_pattern in [f"{container_id}.cmd", f"{container_id}.log"]:
            file_path = new_image_path / file_pattern
            if file_path.exists():
                file_path.unlink()
        
        print(f"Committed container {container_id} to image: {new_image_name}")
        return True

    def list_images(self):
        """List all available images"""
        print("IMAGE_ID\t\tSOURCE")
        for image_dir in self.images_path.iterdir():
            if image_dir.is_dir():
                meta_file = image_dir / ".image_meta"
                source = "unknown"
                if meta_file.exists():
                    with open(meta_file, "r") as f:
                        for line in f:
                            if line.startswith("source="):
                                source = line.split("=", 1)[1].strip()
                print(f"{image_dir.name}\t\t{source}")

    def list_containers(self):
        """List all containers"""
        print("CONTAINER_ID\t\tCOMMAND")
        for container_dir in self.containers_path.iterdir():
            if container_dir.is_dir():
                cmd_file = container_dir / f"{container_dir.name}.cmd"
                command = "unknown"
                if cmd_file.exists():
                    with open(cmd_file, "r") as f:
                        command = f.read().strip()
                print(f"{container_dir.name}\t\t{command}")

    def get_logs(self, container_id):
        """Get container logs"""
        if not self.check_exists(container_id, "container"):
            print(f"Error: Container '{container_id}' does not exist")
            return
        
        log_path = self.containers_path / container_id / f"{container_id}.log"
        if log_path.exists():
            with open(log_path, "r") as f:
                print(f.read())
        else:
            print("No logs found")

    def remove(self, name, force=False):
        """Remove image or container"""
        image_path = self.images_path / name
        container_path = self.containers_path / name
        
        if image_path.exists():
            shutil.rmtree(image_path)
            print(f"Removed image: {name}")
        elif container_path.exists():
            shutil.rmtree(container_path)
            print(f"Removed container: {name}")
        else:
            print(f"Error: '{name}' not found")

#!/usr/bin/env python3

def demo_commit_functionality():
    """
    Demonstrate container commit functionality
    """
    print("=== Container Commit Functionality Demo ===\n")
    
    # Initialize container runtime
    runtime = SimpleContainer()
    
    # Step 1: Create base image from existing directory
    print("Step 1: Creating base image from Almalinux extraction...")
    base_image = runtime.init_image("./extracted_almalinux", "almalinux_base")
    if not base_image:
        print("Error: Could not create base image")
        return
    
    print("\nStep 2: Listing available images...")
    runtime.list_images()
    
    # Step 3: Run container and make changes
    print("\nStep 3: Creating container from base image...")
    container_id = runtime.run_container(base_image)
    if not container_id:
        print("Error: Could not create container")
        return
    
    print("\nStep 4: Installing software in container...")
    # Try to install wget (should fail initially)
    print("Testing wget command (should fail)...")
    success = runtime.execute_in_container(container_id, "wget || echo 'wget not found'")
    
    # Install wget using package manager
    print("Installing wget using yum...")
    success = runtime.execute_in_container(container_id, "yum install -y wget")
    
    # Test wget after installation
    print("Testing wget after installation...")
    runtime.execute_in_container(container_id, "wget && echo 'wget is now available'")
    
    # Step 4: Commit container to new image
    print("\nStep 5: Committing container changes to new image...")
    new_image = "almalinux_with_wget"
    runtime.commit_container(container_id, new_image)
    
    print("\nStep 6: Listing images after commit...")
    runtime.list_images()
    
    # Step 5: Test new image
    print("\nStep 7: Creating new container from committed image...")
    new_container = runtime.run_container(new_image)
    if new_container:
        print("Testing wget in new container...")
        runtime.execute_in_container(new_container, "wget --version | head -1")
    
    # Step 6: Show logs
    print(f"\nStep 8: Container logs for {container_id}:")
    runtime.get_logs(container_id)
    
    print("\n=== Demo Complete ===")
    print("Successfully demonstrated:")
    print("✓ Image creation from directory")
    print("✓ Container creation from image") 
    print("✓ Command execution in container")
    print("✓ Container state modification")
    print("✓ Container commit to new image")
    print("✓ New container from committed image")

if __name__ == "__main__":
    demo_commit_functionality()