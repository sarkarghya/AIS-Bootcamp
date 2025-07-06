#!/usr/bin/env python3

# %%
"""
# Container Namespace Isolation

In this exercise, you'll implement namespace isolation for containers, which is a fundamental security mechanism
that provides process, network, and filesystem isolation between containers and the host system.

## Introduction

Linux namespaces are a feature of the Linux kernel that allows processes to have a view of system resources
that differs from other processes. There are several types of namespaces:

- **PID namespace**: Isolates process IDs - processes inside see different PIDs
- **Network namespace**: Isolates network interfaces, routing tables, firewall rules
- **Mount namespace**: Isolates filesystem mount points
- **UTS namespace**: Isolates hostname and domain name
- **IPC namespace**: Isolates inter-process communication resources

This exercise demonstrates how to create a container with proper namespace isolation and test that
the isolation is working correctly.

## Content & Learning Objectives

### Exercise: Namespace Isolation

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~20 minutes on this exercise.

You'll implement a function that runs a process in an isolated container environment using multiple namespaces.
"""

import subprocess
import os
import signal


def create_cgroup(cgroup_name, memory_limit=None):
    """
    Create a cgroup with specified limits
    
    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
    """
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


# %%
if __name__ == "__main__":
    print("Testing namespace isolation...")
    test_namespace_isolation() 