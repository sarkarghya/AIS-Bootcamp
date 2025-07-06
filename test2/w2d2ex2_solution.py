#!/usr/bin/env python3

# %%
"""
# Container Isolation: Chroot Environments

#### Introduction: Understanding Chroot

In this exercise, you'll learn about chroot (change root), one of the fundamental isolation mechanisms used in containers. Chroot creates a new root directory for processes, effectively "jailing" them within a specific directory tree.

Chroot is a Unix system call that changes the apparent root directory for the current running process and its children. This creates an isolated environment where the process cannot access files outside the designated directory tree. While chroot provides basic filesystem isolation, it's not a complete security mechanism on its own - modern containers combine chroot with other isolation techniques like namespaces and cgroups.

Understanding chroot is essential for grasping how containers work under the hood. Docker and other container runtimes use chroot (or more advanced variants) to isolate container filesystems from the host system.

## Content & Learning Objectives

### 1️⃣ Chroot Environment Execution
Implement a function to execute commands within a chrooted environment.

> **Learning Objectives**
> - Understand chroot filesystem isolation
> - Learn how to execute commands in isolated environments
> - Handle subprocess execution and error management
> - Explore the foundation of container filesystem isolation

<details>
<summary>Vocabulary: Chroot Terms</summary>

- **Chroot**: Change root - a system call that changes the apparent root directory
- **Chroot jail**: An isolated environment created by chroot
- **Root directory**: The top-level directory (/) in a filesystem hierarchy
- **Filesystem isolation**: Preventing processes from accessing files outside their designated area
- **Subprocess**: A separate process spawned by the main program

</details>
"""

# %%
import subprocess
import os
from typing import Optional, List, Union

# %%
"""
## Exercise: Implementing Chroot Command Execution

The chroot system call is fundamental to container isolation. It changes the root directory for a process, creating a "jail" where the process can only access files within the specified directory tree.

Your task is to implement a function that:
1. Takes a directory path and optional command
2. Executes the command within the chrooted environment
3. Handles different command formats (string vs list)
4. Provides proper error handling and timeouts
5. Returns the execution result

### Exercise - implement run_chroot

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~20 minutes on this exercise.

Implement the `run_chroot` function that executes commands in a chrooted environment.
"""

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