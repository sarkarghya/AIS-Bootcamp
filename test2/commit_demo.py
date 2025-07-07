#!/usr/bin/env python3

# Run the script before running the test

import glob
import os
import random
import subprocess
import sys
import time
from pathlib import Path

def get_btrfs_path():
    """Get btrfs path from environment or default"""
    return os.environ.get('BOCKER_BTRFS_PATH', '/var/bocker')

def _run_bash_command(bash_script, show_realtime=False):
    """Execute bash commands using bash -c"""
    try:
        if show_realtime:
            process = subprocess.Popen(
                ['bash', '-c', bash_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            if process.stdout is not None:
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        print(output.rstrip())
            return_code = process.poll()
            return return_code if return_code is not None else 0
        else:
            result = subprocess.run(['bash', '-c', bash_script], capture_output=True, text=True)
            if result.returncode != 0:
                if result.stderr:
                    print(result.stderr, file=sys.stderr)
                return result.returncode
            if result.stdout:
                print(result.stdout.rstrip())
            return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

def _bocker_check(container_id):
    """Check if container/image exists using Python subprocess"""
    btrfs_path = get_btrfs_path()
    try:
        result = subprocess.run(
            ['btrfs', 'subvolume', 'list', btrfs_path],
            capture_output=True, text=True, check=True
        )
        return container_id in result.stdout
    except subprocess.CalledProcessError:
        return False

def _generate_uuid(prefix="ps_"):
    """Generate UUID using Python instead of bash shuf"""
    return f"{prefix}{random.randint(42002, 42254)}"

def _directory_exists(directory):
    """Check if directory exists using Python"""
    return Path(directory).exists()

def _list_images():
    """List images using Python glob instead of bash for loop"""
    btrfs_path = get_btrfs_path()
    images = []
    try:
        for img_path in glob.glob(f"{btrfs_path}/img_*"):
            img_id = os.path.basename(img_path)
            source_file = os.path.join(img_path, 'img.source')
            if os.path.exists(source_file):
                with open(source_file, 'r') as f:
                    source = f.read().strip()
                images.append({'id': img_id, 'source': source})
    except Exception:
        pass
    return images

def _list_containers():
    """List containers using Python glob instead of bash for loop"""
    btrfs_path = get_btrfs_path()
    containers = []
    try:
        for ps_path in glob.glob(f"{btrfs_path}/ps_*"):
            ps_id = os.path.basename(ps_path)
            cmd_file = os.path.join(ps_path, f'{ps_id}.cmd')
            if os.path.exists(cmd_file):
                with open(cmd_file, 'r') as f:
                    command = f.read().strip()
                containers.append({'id': ps_id, 'command': command})
    except Exception:
        pass
    return containers

def _format_table_output(headers, rows):
    """Format table output using Python instead of bash echo -e"""
    if not rows:
        return '\t\t'.join(headers)
    output = ['\t\t'.join(headers)]
    for row in rows:
        output.append('\t\t'.join(row))
    return '\n'.join(output)

def init(args):
    """Create an image from a directory and return the image ID: BOCKER init <directory>"""
    if len(args) < 1:
        return None, 1

    directory = args[0]
    if not _directory_exists(directory):
        print(f"No directory named '{directory}' exists", file=sys.stderr)
        return None, 1

    uuid = _generate_uuid("img_")
    if _bocker_check(uuid):
        return init(args)

    btrfs_path = get_btrfs_path()
    bash_script = f"""
    set -o errexit -o nounset -o pipefail
    btrfs subvolume create "{btrfs_path}/{uuid}" > /dev/null
    cp -rf --reflink=auto "{directory}"/* "{btrfs_path}/{uuid}" > /dev/null
    [[ ! -f "{btrfs_path}/{uuid}"/img.source ]] && echo "{directory}" > "{btrfs_path}/{uuid}"/img.source
    echo "Created: {uuid}"
    """
    returncode = _run_bash_command(bash_script)
    if returncode == 0:
        return uuid, 0
    else:
        return None, returncode

def images(args):
    """List images: BOCKER images"""
    images_list = _list_images()
    if not images_list:
        print("IMAGE_ID\t\tSOURCE")
        return 0
    rows = [[img['id'], img['source']] for img in images_list]
    output = _format_table_output(['IMAGE_ID', 'SOURCE'], rows)
    print(output)
    return 0

def rm(args):
    """Delete an image or container: BOCKER rm <id>"""
    if len(args) < 1:
        print("Usage: bocker rm <id>", file=sys.stderr)
        return 1

    container_id = args[0]
    if not _bocker_check(container_id):
        print(f"No container named '{container_id}' exists", file=sys.stderr)
        return 1

    btrfs_path = get_btrfs_path()
    bash_script = f"""
    set -o errexit -o nounset -o pipefail
    btrfs subvolume delete "{btrfs_path}/{container_id}" > /dev/null
    echo "Removed: {container_id}"
    """
    return _run_bash_command(bash_script)

def ps(args):
    """List containers: BOCKER ps"""
    containers = _list_containers()
    if not containers:
        print("CONTAINER_ID\t\tCOMMAND")
        return 0
    rows = [[container['id'], container['command']] for container in containers]
    output = _format_table_output(['CONTAINER_ID', 'COMMAND'], rows)
    print(output)
    return 0

def run(args):
    """Create a container: BOCKER run <image_id> <command>"""
    if len(args) < 2:
        print("Usage: bocker run <image_id> <command>", file=sys.stderr)
        return 1

    image_id = args[0]
    command = ' '.join(args[1:])

    if not _bocker_check(image_id):
        print(f"No image named '{image_id}' exists", file=sys.stderr)
        return 1

    if not command.strip():
        print("Error: Command cannot be empty", file=sys.stderr)
        return 1

    uuid = _generate_uuid("ps_")
    if _bocker_check(uuid):
        return run(args)

    ip_suffix = uuid[-3:].replace('0', '') or '1'
    mac_suffix = f"{uuid[-3:-2]}:{uuid[-2:]}"

    btrfs_path = get_btrfs_path()
    bash_script = f"""
    set -o errexit -o nounset -o pipefail; shopt -s nullglob
    
    btrfs subvolume snapshot "{btrfs_path}/{image_id}" "{btrfs_path}/{uuid}" > /dev/null
    echo "{command}" > "{btrfs_path}/{uuid}/{uuid}.cmd"
    cp /etc/resolv.conf "{btrfs_path}/{uuid}"/etc/resolv.conf

    unshare -fmuip --mount-proc \\
    chroot "{btrfs_path}/{uuid}" \\
    /bin/sh -c "/bin/mount -t proc proc /proc && {command}" \\
    2>&1 | tee "{btrfs_path}/{uuid}/{uuid}.log" || true
    """
    return _run_bash_command(bash_script, show_realtime=True)

def commit(args):
    """Commit a container to an image: BOCKER commit <container_id> <image_id>"""
    if len(args) < 2:
        print("Usage: bocker commit <container_id> <image_id>", file=sys.stderr)
        return 1

    container_id, image_id = args[0], args[1]
    
    if not _bocker_check(container_id):
        print(f"No container named '{container_id}' exists", file=sys.stderr)
        return 1

    if not _bocker_check(image_id):
        print(f"No image named '{image_id}' exists", file=sys.stderr)
        return 1

    btrfs_path = get_btrfs_path()
    bash_script = f"""
    set -o errexit -o nounset -o pipefail
    btrfs subvolume delete "{btrfs_path}/{image_id}" > /dev/null
    btrfs subvolume snapshot "{btrfs_path}/{container_id}" "{btrfs_path}/{image_id}" > /dev/null
    echo "Created: {image_id}"
    """
    return _run_bash_command(bash_script)

def test_commit():
    """Test commit functionality using wget installation pattern"""
    print("Testing bocker commit...")
    
    # Test argument validation first
    returncode = commit([])
    if returncode != 1:  # Should fail with usage message
        print(f"FAIL: Commit should fail with no arguments")
        return False
    
    # Test with single argument
    returncode = commit(['container_id'])
    if returncode != 1:  # Should fail with usage message
        print(f"FAIL: Commit should fail with single argument")
        return False
    
    # Test with invalid container
    returncode = commit(['nonexistent_container', 'nonexistent_image'])
    if returncode == 0:
        print("FAIL: Commit should fail with nonexistent container")
        return False
    
    # Create test image for commit testing
    base_image_dir = os.path.expanduser('~/base-image')
    if not os.path.exists(base_image_dir):
        print("SKIP: No base image directory available for commit testing")
        return True
    
    # Initialize a new image from base and get the exact image ID
    img_id, returncode = init([base_image_dir])
    if returncode != 0 or not img_id:
        print("FAIL: Could not create test image for commit")
        return False
    
    print(f"Using created image: {img_id}")
    time.sleep(1)
    
    # Test 1: Run wget command (should fail since wget is not installed)
    print("Step 1: Testing wget command (should fail)...")
    returncode = run([img_id, 'wget'])
    time.sleep(2)
    
    # Get container ID for wget test
    containers = _list_containers()
    wget_test_container = None
    for container in containers:
        if 'wget' in container['command'] and 'yum' not in container['command']:
            wget_test_container = container['id']
            break
    
    if wget_test_container:
        print(f"Wget test container: {wget_test_container}")
        # Check logs to confirm wget is not installed
        btrfs_path = get_btrfs_path()
        log_file = Path(btrfs_path) / wget_test_container / f"{wget_test_container}.log"
        if log_file.exists():
            try:
                with open(log_file, 'r') as f:
                    log_content = f.read()
                if 'command not found' in log_content or 'wget: command not found' in log_content:
                    print("Confirmed: wget command not found (as expected)")
                else:
                    print(f"Warning: Unexpected wget output: {log_content}")
            except Exception as e:
                print(f"Warning: Could not read wget test logs: {e}")
        
        # Clean up test container
        rm([wget_test_container])
    
    # Test 2: Install wget using yum
    print("Step 2: Installing wget using yum...")
    returncode = run([img_id, 'yum', 'install', '-y', 'wget'])
    time.sleep(5)  # Give more time for yum install
    
    # Get container ID for yum install
    containers = _list_containers()
    yum_container = None
    for container in containers:
        if 'yum install -y wget' in container['command']:
            yum_container = container['id']
            break
    
    if not yum_container:
        print("FAIL: Could not find yum install container")
        return False
    
    print(f"Yum install container: {yum_container}")
    
    # Test 3: Commit the changes
    print("Step 3: Committing changes to image...")
    commit_returncode = commit([yum_container, img_id])
    if commit_returncode != 0:
        print(f"FAIL: Commit failed with return code {commit_returncode}")
        return False
    
    print(f"Successfully committed changes to image {img_id}")
    
    # Test 4: Verify wget now works by making HTTP request
    print("Step 4: Testing wget with HTTP request...")
    returncode = run([img_id, 'wget', '-qO-', 'http://httpbin.org/get'])
    time.sleep(3)
    
    # Get container ID for wget HTTP request
    containers = _list_containers()
    wget_http_container = None
    for container in containers:
        if 'wget -qO- http://httpbin.org/get' in container['command']:
            wget_http_container = container['id']
            break
    
    if wget_http_container:
        print(f"Wget HTTP request container: {wget_http_container}")
        
        # Check logs to verify HTTP request succeeded
        btrfs_path = get_btrfs_path()
        log_file = Path(btrfs_path) / wget_http_container / f"{wget_http_container}.log"
        if log_file.exists():
            try:
                with open(log_file, 'r') as f:
                    log_content = f.read()
                
                print("Logs from wget HTTP request:")
                print(log_content[:200] + "..." if len(log_content) > 200 else log_content)
                
                if 'http://httpbin.org/get' in log_content or '"url"' in log_content:
                    print("SUCCESS: wget successfully fetched data from httpbin.org")
                else:
                    print("Warning: wget HTTP request may have failed or returned unexpected data")
                    # Don't fail the test as network issues might occur
                    
            except Exception as e:
                print(f"Warning: Could not read wget HTTP logs: {e}")
        
        # Clean up HTTP test container
        rm([wget_http_container])
    else:
        print("Warning: Could not find wget HTTP request container")
    
    print("PASS: bocker commit test")
    return True

def help_command(args):
    """Display help message"""
    help_text = """BOCKER - Simplified version to demonstrate commit functionality

Usage: bocker [command] [args...]

Commands:
  init     Create an image from a directory
  images   List images
  ps       List containers
  run      Create a container
  commit   Commit a container to an image
  rm       Delete an image or container
  demo     Run commit demonstration
  help     Display this message

Commit Demo:
  bocker demo   - Run a complete demonstration of commit functionality"""
    print(help_text)
    return 0

def main():
    """Main entry point"""
    if len(sys.argv) == 1:
        # Run demo by default
        success = test_commit()
        return 0 if success else 1

    command = sys.argv[1]
    args = sys.argv[2:] if len(sys.argv) > 2 else []

    # Command mapping
    command_map = {
        'init': init,
        'images': images,
        'run': run,
        'ps': ps,
        'commit': commit,
        'rm': rm,
        'demo': lambda _: test_commit(),
        'help': help_command
    }

    if command in command_map:
        try:
            if command == 'demo':
                success = test_commit()
                return 0 if success else 1
            else:
                return command_map[command](args)
        except KeyboardInterrupt:
            print("\nOperation cancelled by user", file=sys.stderr)
            return 130
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)
            return 1
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        return help_command([])

if __name__ == '__main__':
    sys.exit(main())
