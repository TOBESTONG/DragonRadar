// dragonball.go
package dragonball

import (
	"fmt"
	"io"
	"io/ioutil"
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
	BridgeName string `json:"bridge_name"`
	BridgeIP   string `json:"bridge_ip"`
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
    cfg            *Config
    os             string
    workdir        string
    sshKey         string
    sshUser        string
    sshHost        string
    sshPort        int
    dbsCmd         *exec.Cmd
    merger         *vmimpl.OutputMerger
    index          int
    debug          bool
    timeouts       targets.Timeouts
    rpipe          io.ReadCloser
    wpipe          io.WriteCloser
    guestIP        string
    args           []string
    forwardedPorts [][2]int // [][{hostPort, guestPort}]
}


func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Count:   1,
		Vcpu:    1,
		MaxVcpu: 1,
		MemSize: 1024,
		BridgeIP: "192.168.100.1/24",
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


	if cfg.BridgeName == "" {
        cfg.BridgeName = "br_syzkaller"
    }
    if cfg.BridgeIP == "" {
        cfg.BridgeIP = "192.168.100.1/24"
    }
	// Set up the network bridge
	if err := setupBridge(cfg.BridgeName, cfg.BridgeIP); err != nil {
        return nil, fmt.Errorf("failed to set up network bridge: %w", err)
    }

	pool := &Pool{
		env: env,
		cfg: cfg,
	}
	return pool, nil
}

func setupBridge(bridgeName, bridgeIP string) error {
    // Check if the bridge exists
	_, err := osutil.RunCmd(time.Minute, "", "ip", "link", "show", bridgeName)
    if err != nil {
        log.Logf(0, "Bridge %s not found, creating...", bridgeName)
        // The bridge does not exist, create it
		cmds := [][]string{
            {"ip", "link", "add", bridgeName, "type", "bridge"},
            {"ip", "addr", "add", bridgeIP, "dev", bridgeName},
            {"ip", "link", "set", bridgeName, "up"},
        }
        for _, cmd := range cmds {
            _, err := osutil.RunCmd(time.Minute, "", cmd[0], cmd[1:]...)
            if err != nil {
                return fmt.Errorf("failed to run command %v: %w", cmd, err)
            }
        }
    } else {
        log.Logf(0, "Bridge %s already exists", bridgeName)
        // Bridge exists, check if there is an IP address
		outputAddr, err := osutil.RunCmd(time.Minute, "", "ip", "addr", "show", "dev", bridgeName)
        if err != nil {
            return fmt.Errorf("failed to get IP address of bridge %s: %w", bridgeName, err)
        }
        if !strings.Contains(string(outputAddr), bridgeIP) {
			log.Logf(0, "Bridge %s does not have IP %s, assigning...", bridgeName, bridgeIP)
			cmds := [][]string{
				{"ip", "addr", "add", bridgeIP, "dev", bridgeName},
				{"ip", "link", "set", bridgeName, "up"},
			}
			for _, cmd := range cmds {
				_, err := osutil.RunCmd(time.Minute, "", cmd[0], cmd[1:]...)
				if err != nil {
					if !strings.Contains(err.Error(), "Address already assigned") {
						return fmt.Errorf("failed to run command %v: %w", cmd, err)
					}
				}
			}
		} else {
			log.Logf(0, "Bridge %s already has IP %s", bridgeName, bridgeIP)
		}
		
    }
    return nil
}



func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
    sshKey := pool.env.SSHKey
    sshUser := pool.env.SSHUser

    // Extract the network portion of the bridge IP address
    bridgeIP := strings.Split(pool.cfg.BridgeIP, "/")[0]
    ipParts := strings.Split(bridgeIP, ".")
    if len(ipParts) != 4 {
        return nil, fmt.Errorf("invalid bridge IP address: %s", bridgeIP)
    }
    // Using the same network segment, assign the IP address of the virtual machine
    guestIP := fmt.Sprintf("%s.%s.%s.%d", ipParts[0], ipParts[1], ipParts[2], index+2)
    // Extract gateway IP address
    gatewayIP := bridgeIP
    if err := prepareInitScript(workdir, sshKey, guestIP, gatewayIP); err != nil {
        return nil, fmt.Errorf("failed to prepare init.sh: %w", err)
    }
	initScriptPath := filepath.Join(workdir, "init.sh")
    content, err := ioutil.ReadFile(initScriptPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read init.sh: %w", err)
    }

    fmt.Println("init.sh contents: ")
    fmt.Println(string(content))

    for i := 0; ; i++ {
        inst, err := pool.ctor(workdir, sshKey, sshUser, index, guestIP)
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




func (pool *Pool) ctor(workdir, sshkey, sshuser string, index int, guestIP string) (*instance, error) {
    inst := &instance{
        index:    index,
        cfg:      pool.cfg,
        debug:    pool.env.Debug,
        os:       pool.env.OS,
        workdir:  workdir,
        sshKey:   sshkey,
        sshUser:  sshuser,
        timeouts: pool.env.Timeouts,
        guestIP:  guestIP, 
    }
    closeInst := inst
    defer func() {
        if closeInst != nil {
            closeInst.Close()
        }
    }()

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



func prepareInitScript(workdir, sshKey, guestIP, gatewayIP string) error {
    initScriptContent := strings.Replace(initScript, "{{KEY}}", sshKey, -1)
    initScriptContent = strings.Replace(initScriptContent, "{{GUEST_IP}}", guestIP, -1)
    initScriptContent = strings.Replace(initScriptContent, "{{GATEWAY_IP}}", gatewayIP, -1)
    initScriptPath := filepath.Join(workdir, "init.sh")
    if err := osutil.WriteExecFile(initScriptPath, []byte(initScriptContent)); err != nil {
        return fmt.Errorf("failed to write init.sh to shared directory: %w", err)
    }
    return nil
}





func (inst *instance) boot(tapInterface string) error {
	// Assign an unused TCP port for SSH port forwarding
	inst.sshPort = vmimpl.UnusedTCPPort()
	inst.sshHost = "localhost"

	args := inst.buildDbsCliArgs(tapInterface)
	inst.args = args 
	
	// Create the command
	cmd := osutil.Command(inst.cfg.DbsCli, args...)
	cmd.Dir = inst.workdir
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
		return fmt.Errorf("failed to start %v %+v: %w", inst.cfg.DbsCli, args, err)
	}
	inst.wpipe.Close()
	inst.wpipe = nil

	// Start the output merger
	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	inst.merger = vmimpl.NewOutputMerger(tee)
	inst.merger.Add("dbs-cli", inst.rpipe)
	inst.rpipe = nil

	var bootOutput []byte
    bootOutputStop := make(chan bool)
    go func() {
        for {
            select {
            case out := <-inst.merger.Output:
                bootOutput = append(bootOutput, out...)
            case <-bootOutputStop:
                close(bootOutputStop)
                return
            }
        }
    }()

	// Set up port forwarding using iptables
    if err := setupPortForwarding(inst.sshPort, inst.guestIP, 22); err != nil {
        bootOutputStop <- true
        <-bootOutputStop
        return fmt.Errorf("failed to set up port forwarding: %w", err)
    }

	// Wait for SSH to become available
	log.Logf(0, "Waiting for SSH to become available on %s:%d", inst.sshHost, inst.sshPort)
	if err := vmimpl.WaitForSSH(inst.debug, 10*time.Minute*inst.timeouts.Scale, inst.sshHost,
        inst.sshKey, inst.sshUser, inst.os, inst.sshPort, inst.merger.Err, false); err != nil {
        bootOutputStop <- true
        <-bootOutputStop
        log.Logf(0, "Failed to connect via SSH: %v", err)
        return vmimpl.MakeBootError(err, bootOutput)
    }
    bootOutputStop <- true
	return nil
}

func (inst *instance) Close() error {
    if inst.dbsCmd != nil {
        // Force terminate the dbs-cli process
        if err := inst.dbsCmd.Process.Kill(); err != nil {
            log.Logf(0, "failed to kill VM process: %v", err)
        }
        inst.dbsCmd.Wait()
    }

    // Make sure all resources are cleaned up
    if inst.merger != nil {
        inst.merger.Wait()
    }
    if inst.rpipe != nil {
        inst.rpipe.Close()
    }
    if inst.wpipe != nil {
        inst.wpipe.Close()
    }

    // Clean up the TAP interface
    tapInterface := fmt.Sprintf("tap%d", inst.index)
    if _, err := osutil.RunCmd(time.Minute, "", "ip", "link", "set", tapInterface, "down"); err != nil {
        log.Logf(0, "failed to set TAP interface down: %v", err)
    }
    if _, err := osutil.RunCmd(time.Minute, "", "ip", "tuntap", "del", "mode", "tap", tapInterface); err != nil {
        log.Logf(0, "failed to delete TAP interface: %v", err)
    }

    // Clean up SSH port forwarding rules
    cleanupPortForwarding(inst.sshPort, inst.guestIP, 22)

    // Clean up other forwarded ports
    for _, fp := range inst.forwardedPorts {
        hostPort := fp[0]
        guestPort := fp[1]
        cleanupPortForwarding(hostPort, inst.guestIP, guestPort)
    }

    return nil
}


func (inst *instance) setupTapInterface(tapName string) error {
    bridgeName := inst.cfg.BridgeName
    cmds := [][]string{
        {"ip", "tuntap", "add", "dev", tapName, "mode", "tap"},
        {"ip", "link", "set", tapName, "up"},
        {"ip", "link", "set", tapName, "master", bridgeName},
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
		//Forward the hostPort's port to the virtual machine's guestIP:guestPort
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
		//Remove the previously added DNAT rule from the PREROUTING chain of the nat table
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
    if port == 0 {
        return "", fmt.Errorf("vm/dragonball: forward port is zero")
    }

    hostPort := vmimpl.UnusedTCPPort()
    if err := setupPortForwarding(hostPort, inst.guestIP, port); err != nil {
        return "", fmt.Errorf("failed to set up port forwarding: %w", err)
    }

    // Save forwarded port information
    inst.forwardedPorts = append(inst.forwardedPorts, [2]int{hostPort, port})

    return fmt.Sprintf("localhost:%v", hostPort), nil
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
const initScript = `#!/bin/bash
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
printf 'auto eth0\niface eth0 inet static\naddress {{GUEST_IP}}\nnetmask 255.255.255.0\ngateway {{GATEWAY_IP}}\n\n' >> /etc/network/interfaces
mkdir -p /etc/network/if-pre-up.d
mkdir -p /etc/network/if-up.d
ifup lo
ifup eth0 || true
echo "root::0:0:root:/root:/bin/bash" > /etc/passwd
mkdir -p /etc/ssh
cp {{KEY}}.pub /root/key.pub
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
/sbin/halt -f
`

