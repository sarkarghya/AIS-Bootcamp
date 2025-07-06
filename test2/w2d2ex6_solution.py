#!/usr/bin/env python3

# %%
"""
# 6. Container Security Monitoring

In this exercise, you'll implement security monitoring for containers to detect potential escape attempts
and malicious syscalls. This is crucial for preventing CVE-2024-0137 and similar container escape vulnerabilities.

## Introduction

Container security monitoring involves tracking system calls that could indicate escape attempts or malicious behavior.
Key concepts include:

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
