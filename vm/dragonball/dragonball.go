// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package dragonball provides a VM backend using dbs-cli to start Dragonball micro-VMs.
// This implementation is specific to Linux hosts.
package dragonball

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
)

// Call vmimpl.Register to register a virtual machine type named "dragonball"
func init() {
	vmimpl.Register("dragonball", vmimpl.Type{
		Ctor:       ctor,
		Overcommit: true,
	})
}

// Config is the parameter in the vm in syzkaller's syzkaller.cfg file, which defines the configuration parameters required to start Kata Containers.
type Config struct {
    KernelPath  string `json:"kernel_path"`  // Path to the kernel image (from --kernel-path)
    Rootfs      string `json:"rootfs"`       // Path to the root filesystem image (from --rootfs)
    BootArgs    string `json:"boot_args"`    // Kernel boot arguments (from --boot-args)
    MemSize     int    `json:"mem_size"`     // Memory size in MiB (from --mem-size)
    Vcpu        int    `json:"vcpu"`         // Number of virtual CPUs (from --vcpu)
    MaxVcpu     int    `json:"max_vcpu"`     // Maximum number of vCPUs (from --max-vcpu)
    LogFile     string `json:"log_file"`     // Log file path (from --log-file)
    LogLevel    string `json:"log_level"`    // Logging level (from --log-level)
    VirNets     string `json:"virnets"`      // Network configuration (from --virnets)
	DbsCli  	string `json:"dbs_cli"`  	 // Path to dbs-cli binary
	Cmdline 	string `json:"cmdline"`  	 // Kernel command line arguments
	Initrd      string `json:"initrd"`
    DbsArgs     string `json:"dbs_args"`
    Count       int    `json:"count"`
}


// Pool represents a group of Dragonball VM instances
type Pool struct {
	env        *vmimpl.Env	// Holds environment configurations (like SSH details, debug info)
	cfg        *Config	// Configuration specific to Dragonball VM instance
}

// Instance represents a single Dragonball VM instance
type instance struct {
    cfg         *Config             // Configuration for this specific instance
    os          string              // OS being used in the guest VM
    kernelPath  string              // Path to the kernel image
    rootfs      string              // Path to the root filesystem image
    bootArgs    string              // Kernel boot arguments
    memory      int                 // Memory size in MiB
    vcpu        int                 // Number of virtual CPUs
    maxVcpu     int                 // Maximum number of vCPUs
    virNets     string              // Network configuration (e.g., TAP device)
    workdir     string              // Working directory for instance
    sshKey      string              // SSH key for accessing the VM
    sshUser     string              // SSH user for VM access
    sshHost     string              // SSH host (typically localhost or VM IP)
    sshPort     int                 // SSH port for connecting to the VM
	dbsCmd  	*exec.Cmd           // The running process of the Dragonball VM
    merger      *vmimpl.OutputMerger // For handling console output/log merging
	index   	int
	debug    	bool
	timeouts 	targets.Timeouts
	rpipe   	io.ReadCloser
    wpipe   	io.WriteCloser
}


// ctor constructor, used to initialize VM Pool
func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Count:       1,
		Vcpu:         1,
		MemSize:         1024,
	}

	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse dragonball VM config: %w", err)
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 128]", cfg.Count)
	}
	if env.Debug && cfg.Count > 1 {
		log.Logf(0, "limiting number of VMs from %v to 1 in debug mode", cfg.Count)
		cfg.Count = 1
	}
	if cfg.DbsCli == "" {
        cfg.DbsCli = "dbs-cli"
    }
    if _, err := exec.LookPath(cfg.DbsCli); err != nil {
        return nil, fmt.Errorf("dbs-cli not found: %w", err)
    }
	if !osutil.IsExist(env.Image) {
		return nil, fmt.Errorf("image file '%v' does not exist", env.Image)
	}
	
	if cfg.Vcpu <= 0 || cfg.Vcpu > 255 {
		return nil, fmt.Errorf("bad dragonball Vcpu: %v, want [1-255]", cfg.Vcpu)
	}
	if cfg.MemSize < 128 || cfg.MemSize > 1048576 {
		return nil, fmt.Errorf("bad dragonball mem: %v, want [128-1048576]", cfg.MemSize)
	}
	// Set default values if not provided
	if cfg.Rootfs == "" {
        cfg.Rootfs = env.Image
    }
    if cfg.KernelPath == "" {
        return nil, fmt.Errorf("kernel_path must be specified in the configuration")
    }
    cfg.KernelPath = osutil.Abs(cfg.KernelPath)
    if cfg.Initrd != "" {
        cfg.Initrd = osutil.Abs(cfg.Initrd)
    }

	pool := &Pool{
		env:        env,
		cfg:        cfg,
	}
	return pool, nil
}

//Implement the Count method of the Pool interface and return the number of VMs running in parallel in the Pool.
func (pool *Pool) Count() int {
	return pool.cfg.Count
}

// The Create method is used to create a new Dragonball VM instance
func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	sshkey := pool.env.SSHKey
	sshuser := pool.env.SSHUser
	/*	//Note reason: This function is called in ctor instead: if err := inst.prepareInitScript()

	// Generate an init.sh script to set up networking and other configurations in the VM.
	initFile := filepath.Join(workdir, "init.sh")
	initScriptWithKey := strings.Replace(initScript, "{{KEY}}", sshkey, -1)
	// Write the script to the VM's working directory
	if err := osutil.WriteExecFile(initFile, []byte(initScriptWithKey)); err != nil {
		return nil, fmt.Errorf("failed to create init.sh file: %w", err)
	}
	*/
	// Ensure TAP interface exists
	if err := setupTapInterface("tap0"); err != nil {
		return nil, fmt.Errorf("failed to set up TAP interface: %w", err)
	}

	// Create the Dragonball instance
	for i := 0; ; i++ {
		inst, err := pool.ctor(workdir, sshkey, sshuser, index)
		if err == nil {
			return inst, nil
		}
		// Handle potential errors in the setup of the virtual machine.
		if i < 1000 && strings.Contains(err.Error(), "could not set up host forwarding rule") {
			continue
		}
		if i < 1000 && strings.Contains(err.Error(), "Device or resource busy") {
			continue
		}
		return nil, err
	}
}

func (pool *Pool) ctor(workdir, sshkey, sshuser string, index int) (*instance, error) {
    inst := &instance{
        index:      index,
        cfg:        pool.cfg,
        debug:      pool.env.Debug,
        os:         pool.env.OS,
        workdir:    workdir,
        sshKey:     sshkey,   
        sshUser:    sshuser,  
        timeouts:   pool.env.Timeouts,
    }
    

	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

	if err := inst.prepareInitScript(); err != nil {
		return nil, fmt.Errorf("failed to prepare init.sh: %w", err)
	}
	// Create the pipes for the VM's console output
	var err error
	inst.rpipe, inst.wpipe, err = osutil.LongPipe()
	if err != nil {
		return nil, err
	}
	
    // Start the VM
	if err := inst.boot(); err != nil {
		return nil, err
	}

	closeInst = nil
	return inst, nil
}



func (inst *instance) boot() error {
    inst.sshPort = vmimpl.UnusedTCPPort()
    args := inst.buildDbsCliArgs()

    if inst.debug {
        log.Logf(0, "starting dbs-cli with args: %v", args)
    }
    // Create the command
    cmd := osutil.Command(inst.cfg.DbsCli, args...)
    if inst.debug {
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr
    } else {
        cmd.Stdout = inst.wpipe
        cmd.Stderr = inst.wpipe
    }
    inst.dbsCmd = cmd

    // Start the command
    if err := cmd.Start(); err != nil {
        if inst.wpipe != nil {
            inst.wpipe.Close()
        }
        return fmt.Errorf("failed to start dbs-cli: %w", err)
    }
    if inst.wpipe != nil {
        inst.wpipe.Close()
        inst.wpipe = nil
    }

    // Start the output merger
    var tee io.Writer
    if inst.debug {
        tee = os.Stdout
    }
    inst.merger = vmimpl.NewOutputMerger(tee)
    inst.merger.Add("dbs-cli", inst.rpipe)
    inst.rpipe = nil

    /*
    // Wait for the API socket to be ready
    apiSockPath := filepath.Join(inst.workdir, "dbs.sock")
    if err := waitForAPISocket(apiSockPath, 10*time.Second); err != nil {
        return fmt.Errorf("API socket not ready: %w", err)
    }
    */

    // Set up port forwarding using iptables
    guestIP := fmt.Sprintf("127.0.0.%d", inst.index+2)
    if err := setupPortForwarding(inst.sshPort, guestIP, 22); err != nil {
        return fmt.Errorf("failed to set up port forwarding: %w", err)
    }
    
    inst.sshHost = "localhost"
    // Wait for SSH to become available
    if err := vmimpl.WaitForSSH(inst.debug, 10*time.Minute*inst.timeouts.Scale, "localhost",
        inst.sshKey, inst.sshUser, inst.os, inst.sshPort, inst.merger.Err, false); err != nil {
        return vmimpl.MakeBootError(err, nil)
    }



    return nil
}

func (inst *instance) Close() error {
    if inst.dbsCmd != nil {
        // Force terminate the dbs-cli process
        if err := inst.dbsCmd.Process.Kill(); err != nil {
            log.Logf(0, "failed to kill VM process: %v", err)
        }

        // Wait for the dbs-cli process to exit
        inst.dbsCmd.Wait()
    }

    // Ensure all resources are cleaned up
    if inst.merger != nil {
        inst.merger.Wait()
    }
    if inst.rpipe != nil {
        inst.rpipe.Close()
    }
    if inst.wpipe != nil {
        inst.wpipe.Close()
    }
    return nil
}



func setupPortForwarding(hostPort int, guestIP string, guestPort int) error {
    // Use iptables to set up port forwarding from hostPort to guestIP:guestPort
    // This requires appropriate privileges (typically root).
    cmds := [][]string{
        {"iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", strconv.Itoa(hostPort), "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", guestIP, guestPort)},
        {"iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"},
    }
    for _, cmd := range cmds {
        _, err := osutil.RunCmd(time.Minute, "", cmd[0], cmd[1:]...)
        if err != nil {
            return fmt.Errorf("failed to run command %v: %w", cmd, err)
        }
    }
    return nil
}

func (inst *instance) Forward(port int) (string, error) {
    // Return the host address and port where the service is forwarded.
    return fmt.Sprintf("localhost:%d", port), nil
}






func setupTapInterface(tapName string) error {
    // Check if the TAP interface already exists
    ifaceExists := func() bool {
        _, err := net.InterfaceByName(tapName)
        return err == nil
    }

    if ifaceExists() {
        return nil // Interface already exists
    }

    // Create TAP interface
    cmds := [][]string{
        {"ip", "tuntap", "add", "dev", tapName, "mode", "tap", "user", fmt.Sprintf("%s", os.Getenv("USER"))},
        {"ip", "addr", "add", "127.0.0.1/58900", "dev", tapName},
        {"ip", "link", "set", tapName, "up"},
    }
    for _, cmd := range cmds {
        _, err := osutil.RunCmd(time.Minute, "", cmd[0], cmd[1:]...)
        if err != nil {
            return fmt.Errorf("failed to run command %v: %w", cmd, err)
        }
    }
    return nil
}

func (inst *instance) prepareInitScript() error {
    sshPubKey, err := os.ReadFile(inst.sshKey + ".pub")
    if err != nil {
        return fmt.Errorf("failed to read SSH public key: %w", err)
    }

    guestIP := fmt.Sprintf("127.0.0.%d", inst.index+2)
    initScriptContent := strings.Replace(initScript, "{{SSH_PUBLIC_KEY}}", strings.TrimSpace(string(sshPubKey)), -1)
    initScriptContent = strings.Replace(initScriptContent, "{{GUEST_IP}}", guestIP, -1)

    initFile := filepath.Join(inst.workdir, "init.sh")
    return osutil.WriteExecFile(initFile, []byte(initScriptContent))
}



func (inst *instance) buildDbsCliArgs() []string {
    guestMAC := fmt.Sprintf("AA:BB:CC:DD:EE:%02X", inst.index)
    tapInterface := "tap0"

    virnetsConfig := fmt.Sprintf(`[{
        "guest_mac":"%s",
        "backend":{
            "type":"virtio",
            "iface_id":"eth0",
            "host_dev_name":"%s",
            "allow_duplicate_mac":true
        }
    }]`, guestMAC, tapInterface)
    
    /*
    fsConfig := fmt.Sprintf(`{
        "sock_path": "%s",
        "tag": "syzkaller",
        "num_queues": 4,
        "queue_size": 1024,
        "cache_size": 2147483648,
        "thread_pool_size": 4,
        "cache_policy": "always",
        "writeback_cache": true,
        "no_open": true,
        "xattr": false,
        "drop_sys_resource": false,
        "mode": "virtio",
        "fuse_killpriv_v2": false,
        "no_readdir": false,
        "use_shared_irq": true,
        "use_generic_irq": true
    }`, filepath.Join(inst.workdir, "vhost-user-fs.sock"))
    */

    bootArgs := inst.cfg.BootArgs + " init=/init.sh"

    args := []string{
        "create",
        "--vcpu", fmt.Sprintf("%d", inst.cfg.Vcpu),
        "--max-vcpu", fmt.Sprintf("%d", inst.cfg.MaxVcpu),
        "--mem-size", fmt.Sprintf("%d", inst.cfg.MemSize),
        "--kernel-path", inst.cfg.KernelPath,
        "--rootfs", inst.cfg.Rootfs,
        "--boot-args", bootArgs, 
        "--virnets", virnetsConfig,
        "--serial-path", "stdio",
        
    }

    if inst.cfg.Initrd != "" {
        args = append(args, "--initrd-path", inst.cfg.Initrd)
    }

    if inst.cfg.LogFile != "" {
        args = append(args, "--log-file", inst.cfg.LogFile)
    }

    if inst.cfg.LogLevel != "" {
        args = append(args, "--log-level", inst.cfg.LogLevel)
    }

    if inst.cfg.DbsArgs != "" {
        args = append(args, strings.Split(inst.cfg.DbsArgs, " ")...)
    }

    return args
}



func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
    <-chan []byte, <-chan error, error) {
    rpipe, wpipe, err := osutil.LongPipe()
    if err != nil {
        return nil, nil, err
    }

    inst.merger.Add("ssh", rpipe)

    sshArgs := vmimpl.SSHArgs(inst.debug, inst.sshKey, 22, false)
    args := append(sshArgs, inst.sshUser+"@"+inst.sshHost, command)
    if inst.debug {
        log.Logf(0, "running command: ssh %#v", args)
    }

    cmd := osutil.Command("ssh", args...)
    cmd.Stdout = wpipe
    cmd.Stderr = wpipe

    if err := cmd.Start(); err != nil {
        wpipe.Close()
        return nil, nil, err
    }
    wpipe.Close()

    return vmimpl.Multiplex(cmd, inst.merger, timeout, vmimpl.MultiplexConfig{
        Stop:  stop,
        Debug: inst.debug,
        Scale: inst.timeouts.Scale,
    })
}




func (inst *instance) Copy(hostSrc string) (string, error) {
    base := filepath.Base(hostSrc)
    vmDst := filepath.Join("/", base)

    args := append(vmimpl.SCPArgs(inst.debug, inst.sshKey, 22, false),
        hostSrc, inst.sshUser+"@"+inst.sshHost+":"+vmDst)
    if inst.debug {
        log.Logf(0, "running command: scp %#v", args)
    }
    _, err := osutil.RunCmd(10*time.Minute*inst.timeouts.Scale, "", "scp", args...)
    if err != nil {
        return "", err
    }
    return vmDst, nil
}









func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
    if output, wait, handled := vmimpl.DiagnoseLinux(rep, inst.ssh); handled {
        return output, wait
    }
    return nil, false
}


func (inst *instance) ssh(args ...string) ([]byte, error) {
    return osutil.RunCmd(time.Minute*inst.timeouts.Scale, "", "ssh", inst.sshArgs(args...)...)
}


func (inst *instance) sshArgs(args ...string) []string {
    sshArgs := vmimpl.SSHArgs(inst.debug, inst.sshKey, inst.sshPort, false)
    sshArgs = append(sshArgs, inst.sshUser+"@"+inst.sshHost)
    return append(sshArgs, args...)
}




// nolint: lll
const initScript = `#!/bin/bash
set -eux

# Configure network interface
ip addr add {{GUEST_IP}}/58900 dev eth0
ip link set eth0 up
ip route add default via 127.0.0.1

# Set up SSH server
mkdir -p /root/.ssh
echo "{{SSH_PUBLIC_KEY}}" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Start SSH server
service ssh start
/usr/sbin/sshd -D

# Keep the VM running
tail -f /dev/null
`



