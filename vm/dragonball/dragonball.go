// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dragonball

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("dragonball", widthoutStats(ctor))
}

func widthoutStats(ctor func(env *vmimpl.Env) (vmimpl.Pool, error)) vmimpl.Type {
	return vmimpl.Type{
		Ctor:       ctor,
		Overcommit: true,
	}
}

type Config struct {
	DbsCli      string `json:"dbs_cli"`      // Path to dbs-cli binary
	Kernel      string `json:"kernel_path"`  // Path to kernel image (vmlinux)
	Rootfs      string `json:"rootfs"`       // Path to rootfs image
	Cpu         int    `json:"cpu"`          // Number of vCPUs
	Mem         int    `json:"mem"`          // Memory size in MB
	NetPrefix   string `json:"net_prefix"`   // Network prefix (e.g., 169.254)
	TapPrefix   string `json:"tap_prefix"`   // TAP device prefix (e.g., "tap" or "db1_")
	IdleTimeout string `json:"idle_timeout"` // Timeout before killing idle VM
	LogFile     string `json:"log_file"`     // Optional log file path
	LogLevel    string `json:"log_level"`    // Optional log level
	Count       int    `json:"count"`        // Injected by syz-manager
	BootArgs    string `json:"boot_args"`    // Extra kernel boot args
}

type Pool struct {
	env     *vmimpl.Env
	cfg     *Config
	workdir string
}

type instance struct {
	cfg       *Config
	index     int
	workdir   string
	debug     bool
	sshUser   string
	sshKey    string
	imageCopy string // Path to the cloned rootfs for this instance

	// Network Configuration
	tapDev  string
	hostIP  string
	guestIP string
	ipMask  string // "255.255.255.252" for /30

	// Runtime
	dbsCmd      *exec.Cmd
	merger      *vmimpl.OutputMerger
	rpipe       io.ReadCloser
	wpipe       io.WriteCloser
	forwardPort int
	closed      chan bool
	timeouts    targets.Timeouts
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Cpu:       1,
		Mem:       1024,
		NetPrefix: "169.254",
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse dragonball config: %w", err)
	}

	if cfg.DbsCli == "" {
		return nil, fmt.Errorf("missing dbs_cli param in config")
	}
	if cfg.Kernel == "" {
		return nil, fmt.Errorf("missing kernel_path param in config")
	}
	if cfg.Rootfs == "" {
		return nil, fmt.Errorf("missing rootfs param in config")
	}
	if !osutil.IsExist(cfg.DbsCli) {
		return nil, fmt.Errorf("dbs-cli binary '%v' does not exist", cfg.DbsCli)
	}
	if !osutil.IsExist(cfg.Kernel) {
		return nil, fmt.Errorf("kernel file '%v' does not exist", cfg.Kernel)
	}
	if !osutil.IsExist(cfg.Rootfs) {
		return nil, fmt.Errorf("rootfs file '%v' does not exist", cfg.Rootfs)
	}

	pool := &Pool{
		env:     env,
		cfg:     cfg,
		workdir: env.Workdir,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(ctx context.Context, workdir string, index int) (vmimpl.Instance, error) {
	// 1. Calculate IP addresses based on Index
	// Network: 169.254.0.0/16 (Link Local to avoid conflicts)
	// Each VM gets a /30 subnet.
	// Index 0: 169.254.0.0/30 -> Host .1, Guest .2
	// Index i: Host = (i*4 + 1), Guest = (i*4 + 2)

	// Using the user-config prefix, default 169.254
	prefix := pool.cfg.NetPrefix
	if prefix == "" {
		prefix = "169.254"
	}

	// Tap Prefix to avoid collision in parallel runs
	tapPrefix := pool.cfg.TapPrefix
	if tapPrefix == "" {
		tapPrefix = "tap"
	}

	base := index * 4
	hostOctet3 := (base + 1) / 256
	hostOctet4 := (base + 1) % 256
	guestOctet3 := (base + 2) / 256
	guestOctet4 := (base + 2) % 256

	hostIP := fmt.Sprintf("%s.%d.%d", prefix, hostOctet3, hostOctet4)
	guestIP := fmt.Sprintf("%s.%d.%d", prefix, guestOctet3, guestOctet4)
	tapDev := fmt.Sprintf("%s%d", tapPrefix, index) // e.g., tap0, db1_0...

	inst := &instance{
		cfg:      pool.cfg,
		index:    index,
		debug:    pool.env.Debug,
		sshUser:  pool.env.SSHUser,
		sshKey:   pool.env.SSHKey,
		workdir:  workdir,
		tapDev:   tapDev,
		hostIP:   hostIP,
		guestIP:  guestIP,
		ipMask:   "255.255.255.252",
		closed:   make(chan bool),
		timeouts: pool.env.Timeouts,
	}

	if err := inst.boot(ctx); err != nil {
		inst.Close()
		return nil, err
	}
	return inst, nil
}

func (inst *instance) boot(ctx context.Context) error {
	// 1. Setup Host Network (TAP & NAT) via a single script
	// This avoids repeated sudo prompts by running one sudo command.
	setupScript := filepath.Join(inst.workdir, "setup_net.sh")
	scriptContent := fmt.Sprintf(`#!/bin/bash
set -eux
# Cleanup
ip link del %s 2>/dev/null || true
# Tap
ip tuntap add dev %s mode tap
ip addr add %s/30 dev %s
ip link set %s up
# NAT
if ! iptables -t nat -C POSTROUTING -s %s/32 -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s %s/32 -j MASQUERADE
fi
`, inst.tapDev, inst.tapDev, inst.hostIP, inst.tapDev, inst.tapDev, inst.guestIP, inst.guestIP)

	if err := osutil.WriteExecFile(setupScript, []byte(scriptContent)); err != nil {
		return fmt.Errorf("failed to create setup script: %w", err)
	}

	// User password is a single space ' '
	// echo ' ' | sudo -S ...
	if _, err := osutil.RunCmd(time.Minute, "", "sh", "-c", fmt.Sprintf("echo ' ' | sudo -S %s", setupScript)); err != nil {
		return fmt.Errorf("network setup failed: %w", err)
	}

	// 4. Prepare Image
	// Reverted QCOW2 optimization because dbs-cli does not support QCOW2 backing files (treats them as Raw).
	// We must copy the image.
	inst.imageCopy = filepath.Join(inst.workdir, "rootfs")
	if err := osutil.CopyFile(inst.cfg.Rootfs, inst.imageCopy); err != nil {
		return fmt.Errorf("failed to copy rootfs: %v", err)
	}

	// 3. Construct Kernel Boot Args
	// Template: ip=<client-ip>:<server-ip>:<gw-ip>:<netmask>:<hostname>:<device>:<autoconf>
	netArg := fmt.Sprintf("ip=%s::%s:%s::eth0:off", inst.guestIP, inst.hostIP, inst.ipMask)

	// Add base args + user supplied args
	// console=ttyS0 is critical for capturing kernel log from stdout
	bootArgs := fmt.Sprintf("console=ttyS0 earlyprintk=ttyS0 reboot=k debug panic=1 pci=off root=/dev/vda %s %s", netArg, inst.cfg.BootArgs)

	// 4. Construct dbs-cli command
	// We need absolute path for dbs-cli
	dbsCli := inst.cfg.DbsCli
	apiSock := filepath.Join(inst.workdir, "dbs.sock")

	// Calculate MAC: 02:FC:00:00:XX:YY based on index
	macOct3 := inst.index / 256
	macOct4 := inst.index % 256
	macAddr := fmt.Sprintf("02:FC:00:00:%02X:%02X", macOct3, macOct4)

	virnetJSON := fmt.Sprintf(`[{"guest_mac":"%s","backend":{"type":"virtio","iface_id":"eth0","host_dev_name":"%s","allow_duplicate_mac":true}}]`, macAddr, inst.tapDev)

	args := []string{
		"--api-sock-path", apiSock,
		"create",
		"--log-file", filepath.Join(inst.workdir, "dbs.log"),
		"--log-level", "Debug",
		"--kernel-path", inst.cfg.Kernel,
		"--rootfs", inst.imageCopy,
		"--boot-args", bootArgs,
		"--mem-size", strconv.Itoa(inst.cfg.Mem),
		"--vcpu", strconv.Itoa(inst.cfg.Cpu),
		"--max-vcpu", strconv.Itoa(inst.cfg.Cpu), // max-vcpu must >= vcpu
		"--virnets", virnetJSON,
	}

	// Enable vsock device for guest-VMM upcall communication (e.g., syz_dragonball_devmgr).
	// dbs-cli creates a virtio-vsock device with hardcoded CID=42; the guest kernel's
	// dragonball_upcall_srv binds on AF_VSOCK port 0xDB to receive device manager commands.
	vsockSock := filepath.Join(inst.workdir, "vsock.sock")
	args = append(args, "--vsock", vsockSock)

	if inst.debug {
		log.Logf(0, "VM-%d: running %v %v", inst.index, dbsCli, args)
	}

	// Use a socket for serial to avoid stdin epoll errors that cause dbs-cli to exit
	serialSock := filepath.Join(inst.workdir, "serial.sock")
	args = append(args, "--serial-path", serialSock)

	// 5. Start Process
	var err error
	inst.rpipe, inst.wpipe, err = osutil.LongPipe()
	if err != nil {
		return err
	}

	inst.merger = vmimpl.NewOutputMerger(nil)
	inst.merger.Add("console", inst.rpipe)

	inst.dbsCmd = osutil.Command(dbsCli, args...)
	inst.dbsCmd.Stdout = inst.wpipe
	inst.dbsCmd.Stderr = inst.wpipe // Merge stderr as well

	if err := inst.dbsCmd.Start(); err != nil {
		inst.wpipe.Close()
		return fmt.Errorf("failed to start dbs-cli: %w", err)
	}

	go func() {
		err := inst.dbsCmd.Wait()
		log.Logf(0, "VM-%d: dbs-cli exited with: %v", inst.index, err)
	}()
	inst.wpipe.Close()
	inst.wpipe = nil

	// Dragonball creates a unix socket for the serial console.
	// We must connect to it to capture kernel output (panic/crash logs).
	var conn net.Conn
	start := time.Now()
	for {
		conn, err = net.Dial("unix", serialSock)
		if err == nil {
			break
		}
		if time.Since(start) > 10*time.Second {
			inst.dbsCmd.Process.Kill()
			inst.dbsCmd.Wait()
			return fmt.Errorf("failed to connect to serial socket %v: %v", serialSock, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	inst.merger.Add("console", conn)

	// 6. Wait for SSH
	// Syzkaller's vmimpl.WaitForSSH handles retries and timeout
	sshOpts := vmimpl.SSHOptions{
		User: inst.sshUser,
		Key:  inst.sshKey,
		Addr: inst.guestIP,
		Port: 22, // Standard port, no forwarding needed for direct IP
	}

	// Dragonball dbs-cli creates the VM and exits with 0 (daemonizes).
	// We must NOT pass inst.merger.Err to WaitForSSH, because it will signal EOF/Exit immediately.
	// Instead, we just wait for SSH. If SSH never comes up, the timeout will catch it.
	if err := vmimpl.WaitForSSH(5*time.Minute, sshOpts, "linux", nil, false, inst.debug); err != nil {
		// Boot failed
		return fmt.Errorf("SSH check failed: %w", err)
	}

	return nil
}

func (inst *instance) Close() error {
	if inst.dbsCmd != nil {
		inst.dbsCmd.Process.Kill()
		inst.dbsCmd.Wait()
	}

	// Cleanup Network
	// Create and run cleanup script
	cleanupScript := filepath.Join(inst.workdir, "cleanup_net.sh")
	scriptContent := fmt.Sprintf(`#!/bin/bash
set -eux
ip link del %s 2>/dev/null || true
iptables -t nat -D POSTROUTING -s %s/32 -j MASQUERADE 2>/dev/null || true
`, inst.tapDev, inst.guestIP)

	if err := osutil.WriteExecFile(cleanupScript, []byte(scriptContent)); err == nil {
		// Ignore errors in cleanup
		// User password is a single space ' '
		osutil.RunCmd(time.Minute, "", "sh", "-c", fmt.Sprintf("echo ' ' | sudo -S %s", cleanupScript))
	}

	if inst.merger != nil {
		inst.merger.Wait()
	}
	return nil
}

func (inst *instance) Forward(port int) (string, error) {
	// We use Reverse SSH Forwarding (-R) which is handled in sshArgs
	// Just record the port here.
	if port == 0 {
		return "", fmt.Errorf("forward port is zero")
	}
	inst.forwardPort = port
	// With Reverse forwarding, the manager listens on 'port' on the Host.
	// The guest connects to localhost:port (which is tunneled to Host:port).
	// So we tell the fuzzer to connect to 127.0.0.1:port
	return fmt.Sprintf("127.0.0.1:%d", port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	base := filepath.Base(hostSrc)
	vmDst := filepath.Join("/", base) // Copy to root or /tmp

	args := []string{
		"-i", inst.sshKey,
		"-F", "/dev/null",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes",
		hostSrc,
		inst.sshUser + "@" + inst.guestIP + ":" + vmDst,
	}

	if inst.debug {
		log.Logf(0, "VM-%d: scp %v", inst.index, args)
	}

	if _, err := osutil.RunCmd(3*time.Minute, "", "scp", args...); err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(ctx context.Context, command string) (<-chan []byte, <-chan error, error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	inst.merger.Add("ssh", rpipe)

	// Build SSH Args
	args := []string{
		"-i", inst.sshKey,
		"-F", "/dev/null",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes",
	}
	if inst.forwardPort != 0 {
		// Reverse forward: Remote(Guest) Port -> Local(Host) Port
		// -R <remote_port>:<local_host>:<local_port>
		// We want Guest to connect to localhost:forwardPort -> Host:forwardPort
		args = append(args, "-R", fmt.Sprintf("%d:127.0.0.1:%d", inst.forwardPort, inst.forwardPort))
	}
	args = append(args, inst.sshUser+"@"+inst.guestIP, command)

	if inst.debug {
		log.Logf(0, "VM-%d: ssh %v", inst.index, args)
	}

	cmd := osutil.Command("ssh", args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe

	if err := cmd.Start(); err != nil {
		wpipe.Close()
		return nil, nil, err
	}
	wpipe.Close()

	return vmimpl.Multiplex(ctx, cmd, inst.merger, vmimpl.MultiplexConfig{
		Debug: inst.debug,
		Scale: inst.timeouts.Scale,
	})
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	return nil, false
}
