package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: container run <command> [args...]")
	}

	switch os.Args[1] {
	case "run":
		run()
	case "child":
		child()
	default:
		log.Fatal("Usage: container run <command> [args...]")
	}
}

func run() {
	fmt.Printf("Running %v as PID %d\n", os.Args[2:], os.Getpid())
	
	// Re-execute ourselves with "child" argument to create new namespaces
	cmd := exec.Command("/proc/self/exe", append([]string{"child"}, os.Args[2:]...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	// Create new namespaces
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS |   // UTS namespace (hostname)
			syscall.CLONE_NEWPID |           // PID namespace
			syscall.CLONE_NEWNS |            // Mount namespace
			syscall.CLONE_NEWIPC |           // IPC namespace
			syscall.CLONE_NEWUSER,           // User namespace
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
	}
	
	must(cmd.Run())
}

func child() {
	fmt.Printf("Running %v as PID %d in container\n", os.Args[2:], os.Getpid())
	
	// Set hostname to make it feel more container-like
	must(syscall.Sethostname([]byte("container")))
	
	// Mount proc filesystem for the new PID namespace
	must(syscall.Mount("proc", "/proc", "proc", 0, ""))
	defer syscall.Unmount("/proc", 0)
	
	// Execute the requested command
	cmd := exec.Command(os.Args[2], os.Args[3:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	must(cmd.Run())
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

