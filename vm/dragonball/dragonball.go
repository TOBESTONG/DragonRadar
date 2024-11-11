// dragonball.go
package dragonball

import (
	"fmt"
	"io"
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

func init() {
	vmimpl.Register("dragonball", vmimpl.Type{
		Ctor:       ctor,
		Overcommit: true,
	})
}

type Config struct {
	KernelPath string `json:"kernel_path"`
	Rootfs     string `json:"rootfs"`
	BootArgs   string `json:"boot_args"`
	MemSize    int    `json:"mem_size"`
	Vcpu       int    `json:"vcpu"`
	MaxVcpu    int    `json:"max_vcpu"`
	LogFile    string `json:"log_file"`
	LogLevel   string `json:"log_level"`
	DbsCli     string `json:"dbs_cli"`
	DbsArgs    string `json:"dbs_args"`
	Count      int    `json:"count"`
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	cfg          *Config
	os           string
	workdir      string
	sshKey       string
	sshUser      string
	sshHost      string
	sshPort      int
	dbsCmd       *exec.Cmd
	merger       *vmimpl.OutputMerger
	index        int
	debug        bool
	timeouts     targets.Timeouts
	rpipe        io.ReadCloser
	wpipe        io.WriteCloser
	sshPublicKey string
	guestIP      string
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Count:   1,
		Vcpu:    1,
		MemSize: 1024,
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
	if cfg.Rootfs == "" {
		cfg.Rootfs = env.Image
	}
	if cfg.KernelPath == "" {
		return nil, fmt.Errorf("kernel_path must be specified in the configuration")
	}
	cfg.KernelPath = osutil.Abs(cfg.KernelPath)

	// Set up the network bridge
	if err := setupBridge(); err != nil {
		return nil, fmt.Errorf("failed to set up network bridge: %w", err)
	}

	pool := &Pool{
		env: env,
		cfg: cfg,
	}
	return pool, nil
}

func setupBridge() error {
	// Create a bridge if not exists
	bridgeName := "br0"
	_, err := osutil.RunCmd(time.Minute, "", "ip", "link", "show", bridgeName)
	if err != nil {
		log.Logf(0, "Failed to detect bridge %s, attempting to create...", bridgeName)
		// Bridge does not exist, create it
		cmds := [][]string{
			{"ip", "link", "add", bridgeName, "type", "bridge"},
			{"ip", "addr", "add", "192.168.100.1/24", "dev", bridgeName},
			{"ip", "link", "set", bridgeName, "up"},
		}
		for _, cmd := range cmds {
			_, err := osutil.RunCmd(time.Minute, "", cmd[0], cmd[1:]...)
			if err != nil {
				return fmt.Errorf("failed to run command %v: %w", cmd, err)
			}
		}
		
	}else {
        log.Logf(0, "Bridge %s already exists", bridgeName)
	}
	return nil
}


func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	sshkey := pool.env.SSHKey
	sshuser := pool.env.SSHUser

	for i := 0; ; i++ {
		inst, err := pool.ctor(workdir, sshkey, sshuser, index)
		if err == nil {
			return inst, nil
		}
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
		index:    index,
		cfg:      pool.cfg,
		debug:    pool.env.Debug,
		os:       pool.env.OS,
		workdir:  workdir,
		sshKey:   sshkey,
		sshUser:  sshuser,
		timeouts: pool.env.Timeouts,
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

	// Ensure TAP interface exists
	tapInterface := fmt.Sprintf("tap%d", inst.index)
	if err := inst.setupTapInterface(tapInterface); err != nil {
		return nil, fmt.Errorf("failed to set up TAP interface: %w", err)
	}

	var err error
	inst.rpipe, inst.wpipe, err = osutil.LongPipe()
	if err != nil {
		return nil, err
	}

	if err := inst.boot(tapInterface); err != nil {
		return nil, err
	}

	closeInst = nil
	return inst, nil
}

func (inst *instance) prepareInitScript() error {
	sshPubKey, err := os.ReadFile(inst.sshKey + ".pub")
	if err != nil {
		return fmt.Errorf("failed to read SSH public key: %w", err)
	}

	inst.sshPublicKey = strings.TrimSpace(string(sshPubKey))

	// Assign unique guest IP based on inst.index
	inst.guestIP = fmt.Sprintf("192.168.100.%d", inst.index+2) // Starts from .2

	// Write init.sh to the shared directory (inst.workdir)
	initScriptContent := strings.Replace(initScript, "{{KEY}}", inst.sshKey, -1)
	initScriptContent = strings.Replace(initScriptContent, "{{GUEST_IP}}", inst.guestIP, -1)
	initScriptPath := filepath.Join(inst.workdir, "init.sh")
	if err := osutil.WriteExecFile(initScriptPath, []byte(initScriptContent)); err != nil {
		return fmt.Errorf("failed to write init.sh to shared directory: %w", err)
	}

	return nil
}

func (inst *instance) boot(tapInterface string) error {
	// Assign an unused TCP port for SSH port forwarding
	inst.sshPort = vmimpl.UnusedTCPPort()

	args := inst.buildDbsCliArgs(tapInterface)

	
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
	log.Logf(0, "Starting dbs-cli with args: %v", args)
	if err := cmd.Start(); err != nil {
		if inst.wpipe != nil {
			inst.wpipe.Close()
		}
		log.Logf(0, "Failed to start dbs-cli: %v", err) 
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

	// Set up port forwarding using iptables
	if err := setupPortForwarding(inst.sshPort, inst.guestIP, 22); err != nil {
		return fmt.Errorf("failed to set up port forwarding: %w", err)
	}

	inst.sshHost = "localhost"
	// Wait for SSH to become available
	log.Logf(0, "Waiting for SSH to become available on %s:%d", inst.sshHost, inst.sshPort)
	if err := vmimpl.WaitForSSH(inst.debug, 10*time.Minute*inst.timeouts.Scale, inst.sshHost,
		inst.sshKey, inst.sshUser, inst.os, inst.sshPort, inst.merger.Err, false); err != nil {
		log.Logf(0, "Failed to connect via SSH: %v", err)
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

	// Clean up the tap interface
	tapInterface := fmt.Sprintf("tap%d", inst.index)
	osutil.RunCmd(time.Minute, "", "ip", "link", "set", tapInterface, "down")
	osutil.RunCmd(time.Minute, "", "ip", "tuntap", "del", "mode", "tap", tapInterface)

	// Clean up port forwarding rules
	cleanupPortForwarding(inst.sshPort, inst.guestIP, 22)

	return nil
}

func (inst *instance) setupTapInterface(tapName string) error {
	// Create TAP interface
	cmds := [][]string{
		{"ip", "tuntap", "add", "dev", tapName, "mode", "tap"},
		{"ip", "link", "set", tapName, "up"},
		{"ip", "link", "set", tapName, "master", "br0"},
	}
	for _, cmd := range cmds {
		_, err := osutil.RunCmd(time.Minute, "", cmd[0], cmd[1:]...)
		if err != nil {
			return fmt.Errorf("failed to run command %v: %w", cmd, err)
		}
	}
	return nil
}

func (inst *instance) buildDbsCliArgs(tapInterface string) []string {
	guestMAC := fmt.Sprintf("AA:BB:CC:DD:EE:%02X", inst.index)

	virnetsConfig := fmt.Sprintf(`[{
		"guest_mac":"%s",
		"backend":{
			"type":"virtio",
			"iface_id":"eth0",
			"host_dev_name":"%s",
			"allow_duplicate_mac":true
		}
	}]`, guestMAC, tapInterface)

	fsConfig := fmt.Sprintf(`{
		"sock_path": "%s",
		"tag": "syzkaller",
		"num_queues": 1,
		"queue_size": 1024,
		"cache_size": 2147483648,
		"thread_pool_size": 1,
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

	bootArgs := inst.cfg.BootArgs + " init=/init"

	args := []string{
		"create",
		"--vcpu", fmt.Sprintf("%d", inst.cfg.Vcpu),
		"--max-vcpu", fmt.Sprintf("%d", inst.cfg.MaxVcpu),
		"--mem-size", fmt.Sprintf("%d", inst.cfg.MemSize),
		"--kernel-path", inst.cfg.KernelPath,
		"--rootfs", inst.cfg.Rootfs,
		"--boot-args", bootArgs,
		"--virnets", virnetsConfig,
		"--fs", fsConfig,
		"--serial-path", "stdio",
		"--vsock", filepath.Join(inst.workdir, "dbs-api.sock"), 
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

func setupPortForwarding(hostPort int, guestIP string, guestPort int) error {
	cmds := [][]string{
		{"iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp",
			"--dport", strconv.Itoa(hostPort), "-j", "DNAT", "--to-destination",
			fmt.Sprintf("%s:%d", guestIP, guestPort)},
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-p", "tcp", "-d", guestIP,
			"-j", "MASQUERADE"},
	}
	for _, cmd := range cmds {
		_, err := osutil.RunCmd(time.Minute, "", cmd[0], cmd[1:]...)
		if err != nil {
			return fmt.Errorf("failed to run command %v: %w", cmd, err)
		}
	}
	return nil
}

func cleanupPortForwarding(hostPort int, guestIP string, guestPort int) {
	cmds := [][]string{
		{"iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp",
			"--dport", strconv.Itoa(hostPort), "-j", "DNAT", "--to-destination",
			fmt.Sprintf("%s:%d", guestIP, guestPort)},
		{"iptables", "-t", "nat", "-D", "POSTROUTING", "-p", "tcp", "-d", guestIP,
			"-j", "MASQUERADE"},
	}
	for _, cmd := range cmds {
		osutil.RunCmd(time.Minute, "", cmd[0], cmd[1:]...)
	}
}

func (inst *instance) Forward(port int) (string, error) {
	// Return the host address and port where the service is forwarded.
	return fmt.Sprintf("localhost:%d", port), nil
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}

	inst.merger.Add("ssh", rpipe)

	sshArgs := vmimpl.SSHArgs(inst.debug, inst.sshKey, inst.sshPort, false)
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

	args := append(vmimpl.SCPArgs(inst.debug, inst.sshKey, inst.sshPort, false),
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
const initScript = `#! /bin/bash
set -eux
mount -t proc none /proc
mount -t sysfs none /sys
mount -t debugfs nodev /sys/kernel/debug/
mount -t tmpfs none /tmp
mount -t tmpfs none /var
mount -t tmpfs none /run
mount -t tmpfs none /etc
mount -t tmpfs none /root
touch /etc/fstab
mkdir /etc/network
mkdir /run/network
printf 'auto lo\niface lo inet loopback\n\n' >> /etc/network/interfaces
printf 'auto eth0\niface eth0 inet static\naddress {{GUEST_IP}}\nnetmask 255.255.255.0\ngateway 192.168.100.1\n\n' >> /etc/network/interfaces
mkdir -p /etc/network/if-pre-up.d
mkdir -p /etc/network/if-up.d
ifup lo
ifup eth0 || true
echo "root::0:0:root:/root:/bin/bash" > /etc/passwd
mkdir -p /etc/ssh
cp {{KEY}}.pub /root/
chmod 0700 /root
chmod 0600 /root/key.pub
mkdir -p /var/run/sshd/
chmod 700 /var/run/sshd
groupadd -g 33 sshd
useradd -u 33 -g 33 -c sshd -d / sshd
cat > /etc/ssh/sshd_config <<EOF
          Port 22
          Protocol 2
          UsePrivilegeSeparation no
          HostKey {{KEY}}
          PermitRootLogin yes
          AuthenticationMethods publickey
          ChallengeResponseAuthentication no
          AuthorizedKeysFile /root/key.pub
          IgnoreUserKnownHosts yes
          AllowUsers root
          LogLevel INFO
          TCPKeepAlive yes
          RSAAuthentication yes
          PubkeyAuthentication yes
EOF
/usr/sbin/sshd -e -D
tail -f /dev/null
/sbin/halt -f
`
