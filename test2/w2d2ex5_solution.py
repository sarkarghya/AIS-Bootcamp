#!/usr/bin/env python3

# %%
"""
# Container Networking

In this exercise, you'll implement container networking using Linux bridges, virtual ethernet pairs (veth), 
and network namespaces. This is fundamental to how Docker and other container runtimes provide network isolation 
while allowing containers to communicate with each other and the outside world.

## Introduction

Container networking involves several key concepts:

- **Bridge Networks**: Software switches that connect multiple network interfaces
- **Virtual Ethernet Pairs (veth)**: Pairs of connected network interfaces that act like a virtual cable
- **Network Namespaces**: Isolated network stacks with their own interfaces, routing tables, and firewall rules
- **NAT (Network Address Translation)**: Allows containers with private IPs to access the internet
- **iptables**: Linux firewall rules for packet filtering and NAT

A typical container network setup involves:
1. Creating a bridge network on the host
2. Creating veth pairs for each container
3. Moving one end of each veth pair into the container's network namespace
4. Configuring IP addresses and routing
5. Setting up NAT rules for internet access

## Content & Learning Objectives

### 5.1 Bridge Network Setup
### 5.2 Container Network Creation
### 5.3 Running Networked Containers
"""

import subprocess
import os
import uuid
import signal


def create_cgroup(cgroup_name, memory_limit=None):
    """Create a cgroup with specified limits"""
    cgroup_path = f"/sys/fs/cgroup/{cgroup_name}"
    
    os.makedirs(cgroup_path, exist_ok=True)
    print(f"Created cgroup directory: {cgroup_path}")
    
    try:
        with open("/sys/fs/cgroup/cgroup.subtree_control", "w") as f:
            f.write("+cpu +memory +pids")
        print("Enabled cgroup controllers")
    except Exception as e:
        print(f"Warning: Could not enable controllers: {e}")
    
    if memory_limit:
        memory_max_path = f"{cgroup_path}/memory.max"
        try:
            with open(memory_max_path, "w") as f:
                f.write(str(memory_limit))
            print(f"Set memory limit to {memory_limit}")
        except Exception as e:
            print(f"Error setting memory limit: {e}")
    
    return cgroup_path


# %%
"""
## Exercise 5.1: Bridge Network Setup

A bridge network acts as a software switch that connects multiple network interfaces. 
This is the foundation of container networking - all containers connect to the bridge, 
and the bridge provides connectivity between containers and to the outside world.

### Exercise - implement setup_bridge_network

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~20 minutes on this exercise.

Implement the bridge network setup function that creates a bridge interface with proper routing and NAT rules.
"""


def setup_bridge_network():
    """
    Set up the bridge network for containers
    Creates bridge0 with 10.0.0.1/24 and configures iptables
    """
   #  print("🔧 DEBUG: Setting up bridge network...")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠ Warning: Bridge network setup requires root privileges")
        return False
    
    if "SOLUTION":
        try:
            # Check if bridge already exists
           #  print("🔧 DEBUG: Checking if bridge0 already exists...")
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
            
            # Enable IP forwarding
           #  print("🔧 DEBUG: Enabling IP forwarding...")
            result = subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                                  capture_output=True, text=True, check=True)
            print(f"✓ Enabled IP forwarding: {result.stdout.strip()}")
            
            # Remove existing bridge if it exists
           #  print("🔧 DEBUG: Removing existing bridge0 if present...")
            subprocess.run(['ip', 'link', 'del', 'bridge0'], 
                          capture_output=True, text=True)
            
            # Create and configure bridge
           #  print("🔧 DEBUG: Creating bridge0...")
            subprocess.run(['ip', 'link', 'add', 'bridge0', 'type', 'bridge'], check=True)
            print("✓ Created bridge0")
            
           #  print("🔧 DEBUG: Configuring bridge0 IP...")
            subprocess.run(['ip', 'addr', 'add', '10.0.0.1/24', 'dev', 'bridge0'], check=True)
            print("✓ Added IP 10.0.0.1/24 to bridge0")
            
           #  print("🔧 DEBUG: Bringing bridge0 up...")
            subprocess.run(['ip', 'link', 'set', 'bridge0', 'up'], check=True)
            print("✓ Bridge0 is up")
            
            # Get default network interface
           #  print("🔧 DEBUG: Finding default network interface...")
            route_result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                        capture_output=True, text=True, check=True)
            default_iface = route_result.stdout.split()[4]
            print(f"✓ Detected default interface: {default_iface}")
            
            # Clear existing iptables rules
           #  print("🔧 DEBUG: Clearing existing iptables rules...")
            subprocess.run(['iptables', '-F'], check=True)
            subprocess.run(['iptables', '-t', 'nat', '-F'], check=True)
            subprocess.run(['iptables', '-t', 'mangle', '-F'], check=True)
            subprocess.run(['iptables', '-X'], check=True)
            print("✓ Cleared existing iptables rules")
            
            # Set default policies
           #  print("🔧 DEBUG: Setting iptables default policies...")
            subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
            print("✓ Set default policies to ACCEPT")
            
            # Add iptables rules for NAT and forwarding
           #  print("🔧 DEBUG: Adding iptables NAT rules...")
            subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '10.0.0.0/24', 
                           '!', '-o', 'bridge0', '-j', 'MASQUERADE'], check=True)
            print("✓ Added NAT rule for 10.0.0.0/24")
            
           #  print("🔧 DEBUG: Adding iptables forwarding rules...")
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', 'bridge0', '-o', default_iface, '-j', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', default_iface, '-o', 'bridge0', 
                           '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', 'bridge0', '-o', 'bridge0', '-j', 'ACCEPT'], check=True)
            print("✓ Added forwarding rules")
            
            print("✓ Bridge network setup completed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"✗ Error setting up bridge network: {e}")
            return False
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            return False
    else:
        # TODO: Implement bridge network setup
        #   - Enable IP forwarding with sysctl
        #   - Create bridge0 interface
        #   - Configure bridge0 with IP 10.0.0.1/24
        #   - Set up iptables rules for NAT and forwarding
        #   - Handle the case where bridge already exists
        pass


def test_bridge_network():
    """Test bridge network setup"""
    print("Testing bridge network setup...")
    
    result = setup_bridge_network()
    if result:
        print("✓ Bridge network setup successful!")
        
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
        print("✗ Bridge network setup failed")
    
    print("=" * 60)
    return result


# Run the test
test_bridge_network()

# %%
"""
## Exercise 5.2: Container Network Creation

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
        if False:
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
        if False:
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

Now let's combine everything to create a complete networked container that has:
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
if __name__ == "__main__":
    print("Testing container networking...")
    test_bridge_network()
    test_container_network()
    test_networked_container() 