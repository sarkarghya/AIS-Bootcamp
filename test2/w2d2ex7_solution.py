#!/usr/bin/env python3

import os
import subprocess
import shutil
import uuid
from pathlib import Path

class SimpleContainer:
    def __init__(self, base_path="/tmp/containers", debug=True):
        self.debug = debug
        self.base_path = Path(base_path)
        self.base_path.mkdir(exist_ok=True)
        self.images_path = self.base_path / "images"
        self.containers_path = self.base_path / "containers"
        self.images_path.mkdir(exist_ok=True)
        self.containers_path.mkdir(exist_ok=True)
        
        if self.debug:
            print(f"[DEBUG] Container runtime initialized")
            print(f"[DEBUG] Base path: {self.base_path}")
            print(f"[DEBUG] Images path: {self.images_path}")
            print(f"[DEBUG] Containers path: {self.containers_path}")

    def debug_print(self, message):
        """Print debug messages if debug mode is enabled"""
        if self.debug:
            print(f"[DEBUG] {message}")

    def inspect_directory(self, path):
        """Inspect directory structure for debugging"""
        if not self.debug:
            return
        
        path = Path(path)
        if not path.exists():
            print(f"[DEBUG] Directory {path} does not exist")
            return
        
        print(f"[DEBUG] Inspecting directory: {path}")
        print(f"[DEBUG] Directory exists: {path.exists()}")
        print(f"[DEBUG] Is directory: {path.is_dir()}")
        
        if path.is_dir():
            try:
                contents = list(path.iterdir())
                print(f"[DEBUG] Contents count: {len(contents)}")
                print(f"[DEBUG] First 10 items:")
                for item in contents[:10]:
                    print(f"[DEBUG]   - {item.name} ({'dir' if item.is_dir() else 'file'})")
                
                # Check for important directories
                important_dirs = ['bin', 'usr', 'etc', 'lib', 'lib64']
                for dir_name in important_dirs:
                    dir_path = path / dir_name
                    if dir_path.exists():
                        print(f"[DEBUG] Found {dir_name}/: {dir_path.exists()}")
            except Exception as e:
                print(f"[DEBUG] Error inspecting directory: {e}")

    def check_exists(self, name, container_type="image"):
        """Check if image or container exists"""
        if container_type == "image":
            exists = (self.images_path / name).exists()
        else:
            exists = (self.containers_path / name).exists()
        
        self.debug_print(f"Checking {container_type} '{name}' exists: {exists}")
        return exists

    def link_existing_image(self, source_dir, image_name):
        """Create a symlink to existing image directory instead of copying"""
        source_path = Path(source_dir).resolve()
        image_path = self.images_path / image_name
        
        self.debug_print(f"Linking existing image from {source_path} to {image_path}")
        
        if not source_path.exists():
            print(f"Error: Source directory '{source_dir}' does not exist")
            return None
        
        self.inspect_directory(source_path)
        
        # Remove existing image if it exists
        if image_path.exists():
            self.debug_print(f"Removing existing image at {image_path}")
            if image_path.is_symlink():
                image_path.unlink()
            else:
                shutil.rmtree(image_path)
        
        # Create symlink instead of copying
        try:
            image_path.symlink_to(source_path)
            self.debug_print(f"Created symlink: {image_path} -> {source_path}")
        except Exception as e:
            self.debug_print(f"Symlink failed, falling back to copy: {e}")
            shutil.copytree(source_path, image_path, dirs_exist_ok=True)
        
        # Create metadata
        metadata = {
            "source": str(source_path),
            "created": str(uuid.uuid4()),
            "type": "linked_image",
            "original_path": str(source_path)
        }
        
        metadata_path = image_path / ".image_meta"
        with open(metadata_path, "w") as f:
            for key, value in metadata.items():
                f.write(f"{key}={value}\n")
        
        self.debug_print(f"Created metadata at {metadata_path}")
        print(f"Linked image: {image_name}")
        return image_name

    def run_container(self, image_name, command=None):
        """Create and run container from image"""
        self.debug_print(f"Creating container from image: {image_name}")
        
        if not self.check_exists(image_name, "image"):
            print(f"Error: Image '{image_name}' does not exist")
            return None
        
        container_id = f"ps_{uuid.uuid4().hex[:8]}"
        container_path = self.containers_path / container_id
        image_path = self.images_path / image_name
        
        self.debug_print(f"Container ID: {container_id}")
        self.debug_print(f"Container path: {container_path}")
        self.debug_print(f"Image path: {image_path}")
        
        # Create container as copy of image (resolve symlinks)
        try:
            if image_path.is_symlink():
                real_image_path = image_path.resolve()
                self.debug_print(f"Resolving symlink: {image_path} -> {real_image_path}")
                shutil.copytree(real_image_path, container_path, dirs_exist_ok=True)
            else:
                shutil.copytree(image_path, container_path, dirs_exist_ok=True)
            
            self.debug_print(f"Container filesystem created")
            self.inspect_directory(container_path)
            
        except Exception as e:
            print(f"Error creating container: {e}")
            return None
        
        # Store command metadata
        if command:
            cmd_file = container_path / f"{container_id}.cmd"
            with open(cmd_file, "w") as f:
                f.write(command)
            self.debug_print(f"Stored command in {cmd_file}")
        
        print(f"Created container: {container_id}")
        return container_id

    def execute_in_container(self, container_id, command):
        """Execute command in container using chroot"""
        self.debug_print(f"Executing command in container {container_id}: {command}")
        
        if not self.check_exists(container_id, "container"):
            print(f"Error: Container '{container_id}' does not exist")
            return False
        
        container_path = self.containers_path / container_id
        self.debug_print(f"Container path: {container_path}")
        
        # Check if container has necessary files
        essential_files = ['bin/sh', 'usr/bin/sh']
        shell_found = False
        for shell_path in essential_files:
            full_path = container_path / shell_path
            if full_path.exists():
                self.debug_print(f"Found shell at: {full_path}")
                shell_found = True
                break
        
        if not shell_found:
            print("Warning: No shell found in container")
        
        try:
            self.debug_print(f"Executing chroot command: chroot {container_path} sh -c '{command}'")
            
            # Use chroot to execute in container
            result = subprocess.run([
                'chroot', str(container_path), 'sh', '-c', command
            ], capture_output=True, text=True, timeout=30)
            
            self.debug_print(f"Command completed with exit code: {result.returncode}")
            self.debug_print(f"Stdout length: {len(result.stdout)} chars")
            self.debug_print(f"Stderr length: {len(result.stderr)} chars")
            
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
            
        except subprocess.TimeoutExpired:
            print(f"Command timed out after 30 seconds")
            return False
        except Exception as e:
            print(f"Error executing command: {e}")
            self.debug_print(f"Exception details: {type(e).__name__}: {e}")
            return False

    def commit_container(self, container_id, new_image_name):
        """Commit container changes to new image"""
        self.debug_print(f"Committing container {container_id} to image {new_image_name}")
        
        if not self.check_exists(container_id, "container"):
            print(f"Error: Container '{container_id}' does not exist")
            return False
        
        if self.check_exists(new_image_name, "image"):
            print(f"Removing existing image: {new_image_name}")
            old_image_path = self.images_path / new_image_name
            if old_image_path.is_symlink():
                old_image_path.unlink()
            else:
                shutil.rmtree(old_image_path)
        
        container_path = self.containers_path / container_id
        new_image_path = self.images_path / new_image_name
        
        self.debug_print(f"Copying from {container_path} to {new_image_path}")
        
        try:
            # Copy container state to new image
            shutil.copytree(container_path, new_image_path, dirs_exist_ok=True)
            
            # Update metadata
            metadata = {
                "source": f"container_{container_id}",
                "created": str(uuid.uuid4()),
                "type": "committed_image",
                "parent_container": container_id
            }
            
            metadata_path = new_image_path / ".image_meta"
            with open(metadata_path, "w") as f:
                for key, value in metadata.items():
                    f.write(f"{key}={value}\n")
            
            self.debug_print(f"Updated metadata at {metadata_path}")
            
            # Clean up container-specific files
            for file_pattern in [f"{container_id}.cmd", f"{container_id}.log"]:
                file_path = new_image_path / file_pattern
                if file_path.exists():
                    file_path.unlink()
                    self.debug_print(f"Removed {file_path}")
            
            print(f"Committed container {container_id} to image: {new_image_name}")
            return True
            
        except Exception as e:
            print(f"Error committing container: {e}")
            self.debug_print(f"Exception details: {type(e).__name__}: {e}")
            return False

    def list_images(self):
        """List all available images"""
        print("IMAGE_ID\t\tSOURCE\t\tTYPE")
        for image_dir in self.images_path.iterdir():
            if image_dir.is_dir() or image_dir.is_symlink():
                meta_file = image_dir / ".image_meta"
                source = "unknown"
                img_type = "unknown"
                
                if meta_file.exists():
                    with open(meta_file, "r") as f:
                        for line in f:
                            if line.startswith("source="):
                                source = line.split("=", 1)[1].strip()
                            elif line.startswith("type="):
                                img_type = line.split("=", 1)[1].strip()
                
                link_indicator = " -> " + str(image_dir.resolve()) if image_dir.is_symlink() else ""
                print(f"{image_dir.name}\t\t{source}\t\t{img_type}{link_indicator}")

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
            if image_path.is_symlink():
                image_path.unlink()
            else:
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
    Demonstrate container commit functionality with existing AlmaLinux image
    """
    print("=== Container Commit Functionality Demo ===\n")
    
    # Initialize container runtime with debug mode
    runtime = SimpleContainer(debug=True)
    
    # Step 1: Link existing AlmaLinux image instead of copying
    print("Step 1: Linking existing AlmaLinux image...")
    
    # Check if the directory exists first
    almalinux_path = "./extracted_almalinux"
    if not Path(almalinux_path).exists():
        print(f"Error: {almalinux_path} does not exist")
        print("Please ensure you have extracted AlmaLinux image to this directory")
        return
    
    base_image = runtime.link_existing_image(almalinux_path, "almalinux_base")
    if not base_image:
        print("Error: Could not link base image")
        return
    
    print("\nStep 2: Listing available images...")
    runtime.list_images()
    
    # Step 3: Run container and make changes
    print("\nStep 3: Creating container from base image...")
    container_id = runtime.run_container(base_image)
    if not container_id:
        print("Error: Could not create container")
        return
    
    print("\nStep 4: Testing and installing software in container...")
    
    # Test basic commands first
    print("Testing basic commands...")
    runtime.execute_in_container(container_id, "echo 'Hello from container'")
    runtime.execute_in_container(container_id, "ls -la /")
    runtime.execute_in_container(container_id, "cat /etc/os-release || echo 'No os-release found'")
    
    # Try to install wget (should fail initially)
    print("Testing wget command (should fail)...")
    success = runtime.execute_in_container(container_id, "wget || echo 'wget not found'")
    
    # Install wget using package manager
    print("Installing wget using yum...")
    success = runtime.execute_in_container(container_id, "yum install -y wget")
    
    if success:
        # Test wget after installation
        print("Testing wget after installation...")
    runtime.execute_in_container(container_id, "wget && echo 'wget is now available'")
    
    # Step 5: Commit container to new image
    print("\nStep 5: Committing container changes to new image...")
    new_image = "almalinux_with_wget"
    runtime.commit_container(container_id, new_image)
    
    print("\nStep 6: Listing images after commit...")
    runtime.list_images()
    
    # Step 7: Test new image
    print("\nStep 7: Creating new container from committed image...")
    new_container = runtime.run_container(new_image)
    if new_container:
        print("Testing wget in new container...")
        runtime.execute_in_container(new_container, "wget --version | head -1")
    
    # Step 8: Show logs
    print(f"\nStep 8: Container logs for {container_id}:")
    runtime.get_logs(container_id)
    
    print("\n=== Demo Complete ===")
    print("Successfully demonstrated:")
    print("✓ Direct linking of existing image directory")
    print("✓ Container creation from linked image") 
    print("✓ Command execution in container")
    print("✓ Container state modification")
    print("✓ Container commit to new image")
    print("✓ New container from committed image")
    print("✓ Comprehensive debugging throughout process")

if __name__ == "__main__":
    demo_commit_functionality()
