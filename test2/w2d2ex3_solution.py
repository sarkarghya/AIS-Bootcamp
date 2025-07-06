#!/usr/bin/env python3

# %%
"""
# Container Resource Management: Cgroups

#### Introduction: Understanding Cgroups

In this exercise, you'll learn about cgroups (control groups), a Linux kernel feature that provides resource management and isolation for containers. Cgroups allow you to limit, account for, and isolate resource usage (CPU, memory, disk I/O, etc.) of groups of processes.

Cgroups are essential for container technology, providing the foundation for resource limits and guarantees. Docker, Kubernetes, and other container orchestration systems rely heavily on cgroups to manage resources fairly and prevent resource starvation.

Understanding cgroups is crucial for:
- Setting memory and CPU limits on containers
- Preventing resource exhaustion attacks
- Implementing fair resource sharing
- Building container orchestration systems

## Content & Learning Objectives

### 1️⃣ Basic Cgroup Creation
Create and configure basic cgroups with memory limits.

> **Learning Objectives**
> - Understand cgroup filesystem structure
> - Learn to create cgroup directories
> - Configure memory limits and controllers

### 2️⃣ Process Assignment
Assign processes to cgroups for resource management.

> **Learning Objectives**
> - Learn how to add processes to cgroups
> - Understand process inheritance in cgroups
> - Handle process assignment errors

### 3️⃣ Combined Cgroup-Chroot Execution
Execute commands with both cgroup limits and chroot isolation.

> **Learning Objectives**
> - Combine multiple isolation mechanisms
> - Understand container-like execution
> - Handle complex execution pipelines

### 4️⃣ Comprehensive Cgroup Setup (Part 1)
Set up cgroups with comprehensive memory management.

> **Learning Objectives**
> - Configure advanced cgroup features
> - Understand memory subsystem options
> - Implement robust memory limits

### 5️⃣ Comprehensive Cgroup Setup (Part 2)
Complete comprehensive memory management with swap control and OOM settings.

> **Learning Objectives**
> - Configure swap and OOM behavior
> - Understand memory pressure handling
> - Implement production-ready memory limits

"""

# %%
import subprocess
import os
import signal
import time
from typing import Optional, List, Union

# %%
"""
## Exercise 1: Basic Cgroup Creation

Cgroups are organized in a hierarchy in the `/sys/fs/cgroup` filesystem. To create a cgroup, you need to create directories and write to control files to configure resource limits.

### Exercise - implement create_cgroup

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~15 minutes on this exercise.

Implement the `create_cgroup` function that creates a basic cgroup with memory limits.
"""

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
## Exercise 2: Process Assignment

Once a cgroup is created, processes can be assigned to it by writing their PIDs to the `cgroup.procs` file. This allows the cgroup to manage resources for those processes.

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
## Exercise 3: Combined Cgroup-Chroot Execution

This exercise combines cgroup resource limits with chroot filesystem isolation, creating a more complete container-like environment.

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

This exercise implements the first part of comprehensive cgroup configuration with better memory management and error handling.

### Exercise - implement create_cgroup_comprehensive (basic setup)

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~15 minutes on this exercise.

Implement the basic setup part of `create_cgroup_comprehensive`.
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
        
        return cgroup_path
    else:
        # TODO: Implement comprehensive cgroup creation - Part 1
        # 1. Create cgroup directory with better error handling
        # 2. Enable controllers with proper error checking
        # 3. Set memory limits with validation
        # 4. Return None if any critical step fails
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

This final exercise completes the comprehensive memory management with swap control and OOM settings.

### Exercise - implement create_cgroup_comprehensive (complete)

> **Difficulty**: 🔴🔴🔴🔴🔴  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~20 minutes on this exercise.

Implement the complete `create_cgroup_comprehensive` function with all advanced features.
"""

def create_cgroup_comprehensive(cgroup_name, memory_limit=None, cpu_limit=None):
    """
    Create a cgroup with comprehensive settings to ensure memory limits work properly
    
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

print("Testing complete comprehensive cgroup creation with memory test...")
test_memory_comprehensive(cgroup_name="demo2", memory_limit="50M")
print("✓ Complete comprehensive cgroup creation tests completed!\n" + "=" * 60)
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