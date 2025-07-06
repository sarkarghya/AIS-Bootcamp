# %% This implementation is not working.

def pivot_root_with_cleanup(new_root, old_root_mountpoint):
    """
    Implement pivot_root with proper cleanup and isolation
    """
    import os
    import subprocess
    
    try:
        # Check privileges
        if os.geteuid() != 0:
            print("Error: Requires root privileges")
            return False
        
        new_root = os.path.abspath(new_root)
        
        # Make new_root a mount point
        subprocess.run(['mount', '--bind', new_root, new_root], check=True)
        
        # Create old root directory
        old_root_path = os.path.join(new_root, old_root_mountpoint.lstrip('/'))
        os.makedirs(old_root_path, exist_ok=True)
        
        # Execute pivot_root
        subprocess.run(['pivot_root', new_root, old_root_path], check=True)
        
        # Change to new root directory
        os.chdir('/')
        
        # Critical: Execute chroot to change running executable
        # This is necessary to free up old root references
        subprocess.run(['chroot', '.', '/bin/sh', '-c', f'''
            # Redirect standard I/O to new root devices
            exec </dev/console >/dev/console 2>&1
            
            # Try to unmount old root
            umount /{old_root_mountpoint} 2>/dev/null || {{
                echo "Warning: Could not unmount old root - may still be busy"
                # Force unmount as last resort
                umount -l /{old_root_mountpoint} 2>/dev/null || true
            }}
            
            echo "pivot_root cleanup completed"
        '''], check=True)
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"pivot_root failed: {e}")
        return False

def test_pivot_root_with_proper_cleanup():
    """
    Test pivot_root with proper process isolation and cleanup
    """
    import os
    import subprocess
    
    print("=== Testing pivot_root with Proper Cleanup ===")
    
    if os.geteuid() != 0:
        print("✗ Requires root privileges")
        return False
    
    chroot_dir = "./extracted_python"
    
    if not os.path.isdir(chroot_dir):
        print(f"✗ Directory {chroot_dir} not found")
        return False
    
    # Create marker file
    marker_file = "/tmp/pivot_test_marker"
    with open(marker_file, 'w') as f:
        f.write("Should be inaccessible after pivot_root")
    
    print(f"✓ Created marker file: {marker_file}")
    
    # Execute in isolated namespace with proper cleanup
    cleanup_script = f'''
import os
import subprocess

def isolated_test():
    try:
        # Create tmpfs for new root
        subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', '/tmp/new_root'], check=True)
        
        # Copy extracted_python contents
        subprocess.run(['cp', '-a', '{os.path.abspath(chroot_dir)}/.', '/tmp/new_root'], check=True)
        
        # Create old_root directory
        os.makedirs('/tmp/new_root/old_root', exist_ok=True)
        
        # Execute pivot_root
        subprocess.run(['pivot_root', '/tmp/new_root', '/tmp/new_root/old_root'], check=True)
        print("✓ pivot_root successful")
        
        # Change to new root
        os.chdir('/')
        
        # Test old root accessibility
        try:
            with open('/old_root{marker_file}', 'r') as f:
                print("✗ Old root still accessible - security issue!")
                return False
        except FileNotFoundError:
            print("✓ Old root marker inaccessible - good isolation")
        
        # Execute chroot to change running executable
        subprocess.run(['chroot', '.', '/bin/sh', '-c', """
            # Redirect I/O to prevent old root references
            exec </dev/console >/dev/console 2>&1
            
            # Unmount old root
            if umount /old_root 2>/dev/null; then
                echo "✓ Old root successfully unmounted"
            else
                echo "! Old root busy, using lazy unmount"
                umount -l /old_root 2>/dev/null || true
            fi
            
            # Verify complete isolation
            if [ -d /old_root ]; then
                if [ "$(ls -A /old_root 2>/dev/null)" ]; then
                    echo "✗ Old root still contains files"
                else
                    echo "✓ Old root directory empty - complete isolation"
                fi
            else
                echo "✓ Old root directory removed - perfect isolation"
            fi
        """], check=True)
        
        return True
        
    except Exception as e:
        print(f"Error: {{e}}")
        return False

isolated_test()
'''
    
    try:
        result = subprocess.run(['unshare', '--mount', '--pid', '--fork', 
                               'python3', '-c', cleanup_script], 
                              capture_output=True, text=True, check=True)
        print(result.stdout)
        
        # Cleanup marker file
        try:
            os.remove(marker_file)
        except:
            pass
            
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"Test failed: {e}")
        if e.stderr:
            print(f"stderr: {e.stderr}")
        return False
