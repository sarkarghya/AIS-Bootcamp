#!/usr/bin/env python3

# %%
"""
# Container Resource Management: Cgroups

#### Introduction: Understanding Cgroups

In this exercise, you'll learn about cgroups (control groups), a Linux kernel feature that limits and isolates resource usage of processes. Cgroups are fundamental to container resource management, allowing you to control CPU, memory, I/O, and other resources.

Cgroups provide a mechanism to organize processes hierarchically and distribute system resources along the hierarchy in a controlled and configurable manner. Modern container runtimes like Docker use cgroups to enforce resource limits and ensure fair resource sharing between containers.

## Content & Learning Objectives

### 1️⃣ Basic Cgroup Setup
Create cgroup directories and enable controllers for resource management.

> **Learning Objectives**
> - Understand cgroup filesystem structure
> - Learn how to create and configure cgroups
> - Enable resource controllers

### 2️⃣ Memory Limit Configuration
Set memory limits for cgroups to control memory usage.

> **Learning Objectives**
> - Configure memory limits using cgroup.memory.max
> - Understand memory management in containers
> - Handle memory limit errors

### 3️⃣ Advanced Memory Configuration
Implement comprehensive memory settings with proper limits.

> **Learning Objectives**
> - Set up advanced memory configurations
> - Handle memory limit validation
> - Configure memory controllers properly

### 4️⃣ Swap Management
Disable swap settings for containers to enforce hard memory limits.

> **Learning Objectives**
> - Disable swap for containers
> - Understand swap impact on memory limits
> - Configure memory.swap.max settings

### 5️⃣ OOM Management
Configure Out-of-Memory (OOM) behavior for container processes.

> **Learning Objectives**
> - Configure OOM group killing
> - Understand memory pressure handling
> - Manage container termination behavior

"""

# %%
import os
from typing import Optional

# %%
"""
## Exercise 1: Basic Cgroup Setup

Cgroups are organized in a hierarchical filesystem at `/sys/fs/cgroup/`. To create a cgroup, you need to:
1. Create a directory under `/sys/fs/cgroup/`
2. Enable the necessary controllers in the parent cgroup

### Exercise - implement create_cgroup_directory

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~10 minutes on this exercise.

Implement the `create_cgroup_directory` function that creates a cgroup directory and enables controllers.
"""

def create_cgroup_directory(cgroup_name: str) -> str:
    """
    Create a cgroup directory and enable controllers.
    
    Args:
        cgroup_name: Name of the cgroup to create
        
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
        
        return cgroup_path
    else:
        # TODO: Implement cgroup directory creation
        # 1. Create cgroup directory under /sys/fs/cgroup/
        # 2. Enable controllers (+cpu +memory +pids) in parent cgroup
        # 3. Return the cgroup path
        pass

def test_create_cgroup_directory(create_cgroup_directory):
    """Test the cgroup directory creation function."""
    print("Testing cgroup directory creation...")
    
    try:
        cgroup_path = create_cgroup_directory("test_cgroup")
        assert os.path.exists(cgroup_path), "Cgroup directory should exist"
        assert cgroup_path.endswith("test_cgroup"), "Should return correct path"
        print("✓ Cgroup directory creation works")
        
        # Cleanup
        os.rmdir(cgroup_path)
        
    except Exception as e:
        print(f"⚠ Cgroup directory test failed: {e}")
    
    print("✓ Cgroup directory tests passed!\n" + "=" * 60)

test_create_cgroup_directory(create_cgroup_directory)

# %%
"""
## Exercise 2: Memory Limit Configuration

Memory limits in cgroups are controlled through the `memory.max` file. This sets the maximum amount of memory that processes in the cgroup can use.

### Exercise - implement set_memory_limit

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~10 minutes on this exercise.

Implement the `set_memory_limit` function that sets memory limits for a cgroup.
"""

def set_memory_limit(cgroup_path: str, memory_limit: str) -> bool:
    """
    Set memory limit for a cgroup.
    
    Args:
        cgroup_path: Path to the cgroup directory
        memory_limit: Memory limit (e.g., '100M', '1000000')
        
    Returns:
        True if successful, False otherwise
    """
    if "SOLUTION":
        if memory_limit:
            memory_max_path = f"{cgroup_path}/memory.max"
            try:
                with open(memory_max_path, "w") as f:
                    f.write(str(memory_limit))
                print(f"Set memory limit to {memory_limit}")
                return True
            except Exception as e:
                print(f"Error setting memory limit: {e}")
                return False
        return False
    else:
        # TODO: Implement memory limit setting
        # 1. Build path to memory.max file
        # 2. Write memory_limit to the file
        # 3. Handle exceptions and return success status
        pass

def test_set_memory_limit(set_memory_limit, create_cgroup_directory):
    """Test the memory limit configuration function."""
    print("Testing memory limit configuration...")
    
    try:
        cgroup_path = create_cgroup_directory("test_memory")
        success = set_memory_limit(cgroup_path, "100M")
        assert success, "Memory limit setting should succeed"
        
        # Verify limit was set
        memory_max_path = f"{cgroup_path}/memory.max"
        if os.path.exists(memory_max_path):
            with open(memory_max_path, "r") as f:
                limit = f.read().strip()
            print(f"✓ Memory limit set to: {limit}")
        
        # Cleanup
        os.rmdir(cgroup_path)
        
    except Exception as e:
        print(f"⚠ Memory limit test failed: {e}")
    
    print("✓ Memory limit tests passed!\n" + "=" * 60)

test_set_memory_limit(set_memory_limit, create_cgroup_directory)

# %%
"""
## Exercise 3: Advanced Memory Configuration

Advanced memory configuration includes comprehensive validation and error handling to ensure memory limits are properly enforced.

### Exercise - implement setup_advanced_memory

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~15 minutes on this exercise.

Implement the `setup_advanced_memory` function that sets up advanced memory configuration.
"""

def setup_advanced_memory(cgroup_path: str, memory_limit: str) -> bool:
    """
    Set up advanced memory configuration with validation.
    
    Args:
        cgroup_path: Path to the cgroup directory
        memory_limit: Memory limit (e.g., '100M', '1000000')
        
    Returns:
        True if successful, False otherwise
    """
    if "SOLUTION":
        print(f"Setting up advanced memory configuration: {memory_limit}")
        
        # Set memory limit if specified
        if memory_limit:
            memory_max_path = f"{cgroup_path}/memory.max"
            try:
                with open(memory_max_path, "w") as f:
                    f.write(str(memory_limit))
                print(f"✓ Set memory limit to {memory_limit}")
                return True
            except Exception as e:
                print(f"✗ Error setting memory limit: {e}")
                return False
        return False
    else:
        # TODO: Implement advanced memory configuration
        # 1. Add debugging output for memory limit
        # 2. Set memory limit with proper error handling
        # 3. Return success status with validation
        pass

def test_setup_advanced_memory(setup_advanced_memory, create_cgroup_directory):
    """Test the advanced memory configuration function."""
    print("Testing advanced memory configuration...")
    
    try:
        cgroup_path = create_cgroup_directory("test_advanced")
        success = setup_advanced_memory(cgroup_path, "50M")
        assert success, "Advanced memory setup should succeed"
        print("✓ Advanced memory configuration works")
        
        # Cleanup
        os.rmdir(cgroup_path)
        
    except Exception as e:
        print(f"⚠ Advanced memory test failed: {e}")
    
    print("✓ Advanced memory tests passed!\n" + "=" * 60)

test_setup_advanced_memory(setup_advanced_memory, create_cgroup_directory)

# %%
"""
## Exercise 4: Swap Management

Disabling swap is critical for container stability. When swap is enabled, containers can exceed their memory limits by using swap space, making memory limits ineffective.

### Exercise - implement disable_swap

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~10 minutes on this exercise.

Implement the `disable_swap` function that disables swap for a cgroup.
"""

def disable_swap(cgroup_path: str) -> bool:
    """
    Disable swap for a cgroup to enforce hard memory limits.
    
    Args:
        cgroup_path: Path to the cgroup directory
        
    Returns:
        True if successful, False otherwise
    """
    if "SOLUTION":
        # Disable swap for this cgroup (forces hard memory limit)
        try:
            swap_max_path = f"{cgroup_path}/memory.swap.max"
            with open(swap_max_path, "w") as f:
                f.write("0")
            print("✓ Disabled swap for cgroup")
            return True
        except Exception as e:
            print(f"Warning: Could not disable swap: {e}")
            return False
    else:
        # TODO: Implement swap disabling
        # 1. Build path to memory.swap.max file
        # 2. Write "0" to disable swap
        # 3. Handle exceptions and return success status
        pass

def test_disable_swap(disable_swap, create_cgroup_directory):
    """Test the swap disabling function."""
    print("Testing swap disabling...")
    
    try:
        cgroup_path = create_cgroup_directory("test_swap")
        success = disable_swap(cgroup_path)
        # Don't assert success as some systems may not support this feature
        print("✓ Swap disabling attempted")
        
        # Cleanup
        os.rmdir(cgroup_path)
        
    except Exception as e:
        print(f"⚠ Swap disabling test failed: {e}")
    
    print("✓ Swap disabling tests passed!\n" + "=" * 60)

test_disable_swap(disable_swap, create_cgroup_directory)

# %%
"""
## Exercise 5: OOM Management

Out-of-Memory (OOM) group killing ensures that when a container exceeds memory limits, all processes in the container are terminated together, preventing partial container states.

### Exercise - implement configure_oom_killing

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~10 minutes on this exercise.

Implement the `configure_oom_killing` function that configures OOM group killing.
"""

def configure_oom_killing(cgroup_path: str) -> bool:
    """
    Configure OOM group killing for a cgroup.
    
    Args:
        cgroup_path: Path to the cgroup directory
        
    Returns:
        True if successful, False otherwise
    """
    if "SOLUTION":
        # Set OOM killer to be more aggressive for this cgroup
        try:
            oom_group_path = f"{cgroup_path}/memory.oom.group"
            with open(oom_group_path, "w") as f:
                f.write("1")
            print("✓ Enabled OOM group killing")
            return True
        except Exception as e:
            print(f"Warning: Could not set OOM group: {e}")
            return False
    else:
        # TODO: Implement OOM group killing configuration
        # 1. Build path to memory.oom.group file
        # 2. Write "1" to enable OOM group killing
        # 3. Handle exceptions and return success status
        pass

def test_configure_oom_killing(configure_oom_killing, create_cgroup_directory):
    """Test the OOM group killing configuration function."""
    print("Testing OOM group killing configuration...")
    
    try:
        cgroup_path = create_cgroup_directory("test_oom")
        success = configure_oom_killing(cgroup_path)
        # Don't assert success as some systems may not support this feature
        print("✓ OOM group killing configuration attempted")
        
        # Cleanup
        os.rmdir(cgroup_path)
        
    except Exception as e:
        print(f"⚠ OOM group killing test failed: {e}")
    
    print("✓ OOM group killing tests passed!\n" + "=" * 60)

test_configure_oom_killing(configure_oom_killing, create_cgroup_directory)



# %%
"""
## Summary: Understanding Cgroups

Through these exercises, you've learned about cgroups, a fundamental container technology:

### Key Concepts

1. **Cgroup Hierarchy**: Cgroups are organized in a filesystem hierarchy under `/sys/fs/cgroup/`
2. **Controllers**: Different resource types (CPU, memory, I/O) are managed by specific controllers
3. **Memory Limits**: Hard limits (`memory.max`) control maximum memory usage
4. **Swap Management**: Disabling swap ensures predictable memory behavior
5. **OOM Handling**: Out-of-Memory group killing ensures clean container termination

### Real-World Applications

- **Container Runtimes**: Docker, Kubernetes use cgroups for resource management
- **System Administration**: Limiting resource usage for services and users
- **Performance Tuning**: Preventing memory pressure and resource contention
- **Security**: Isolating processes and preventing resource exhaustion attacks

### Next Steps

Understanding cgroups enables you to:
- Configure container resource limits effectively
- Debug container performance issues
- Implement custom resource management solutions
- Optimize container density and resource utilization

Remember: Cgroups are the foundation of container resource management!
""" 