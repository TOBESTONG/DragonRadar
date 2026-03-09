# How to Boot Dragonball with dbs-cli

This document describes how to use `dbs-cli` to launch a Dragonball MicroVM for kernel fuzzing with DragonRadar.

## Prerequisites

- A compiled `dbs-cli` binary (from [kata-containers/kata-containers](https://github.com/kata-containers/kata-containers), under `src/dragonball/src/dbs-cli`)
- An **uncompressed** Linux kernel binary (`vmlinux`). Dragonball does **not** support `bzImage`.
- A root filesystem image (e.g., Alpine-based or Debian-based `.img`)
- Host with `sudo` access for TAP device and network configuration

## 1. Kernel Preparation

```bash
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git linux-dbs
cd linux-dbs
git checkout v5.10  # or your target version

make defconfig
make kvm_guest.config
# Apply any additional Kconfig changes for fuzzing (KCOV, KASAN, etc.)
make olddefconfig
make -j$(nproc)
```

### Required Kernel Configs

| Config | Purpose |
|---|---|
| `CONFIG_KVM_GUEST=y` | KVM guest optimizations (x86_64) |
| `CONFIG_VIRTIO_BLK=y` | Block device support via virtio |
| `CONFIG_VIRTIO_NET=y` | Network support via virtio |
| `CONFIG_VIRTIO_CONSOLE=y` | Virtio console support |
| `CONFIG_KCOV=y` | Code coverage for fuzzing |
| `CONFIG_KASAN=y` | Address sanitizer (optional but recommended) |

## 2. Rootfs Preparation

For Syzkaller/DragonRadar, you can use the official `create-image.sh` to generate a Debian-based image, or build a custom Alpine-based minimal image (recommended for performance).

```bash
# Option A: Syzkaller's default Debian image
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh
chmod +x create-image.sh
./create-image.sh
```

## 3. Host Network Setup

Dragonball uses TAP devices for VM networking. Before launching, configure the host-side network:

```bash
# Create TAP device
sudo ip tuntap add tap0 mode tap
sudo ip addr add 172.16.0.1/30 dev tap0
sudo ip link set tap0 up

# Enable IP forwarding and NAT (for internet access inside VM)
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tap0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o tap0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

> **Note**: When using DragonRadar's `syz-manager`, the adapter layer handles TAP creation and network setup automatically via a generated script. Manual setup is only needed for standalone `dbs-cli` usage.

## 4. Launching a VM with dbs-cli

### Basic Command

```bash
sudo dbs-cli create \
    --log-file dbs-cli.log \
    --kernel-path /path/to/vmlinux \
    --rootfs /path/to/rootfs.img \
    --boot-args "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda \
        ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off" \
    --mem-size 2048 \
    --vcpu 2 \
    --max-vcpu 2 \
    --virnets '[{
        "guest_mac":"06:00:AC:10:00:02",
        "backend":{
            "type":"virtio",
            "iface_id":"eth0",
            "host_dev_name":"tap0",
            "allow_duplicate_mac":true
        }
    }]'
```

### Key Parameters

| Parameter | Required | Description |
|---|:---:|---|
| `--kernel-path` | Yes | Path to uncompressed `vmlinux` kernel binary |
| `--rootfs` | Yes | Path to the root filesystem image |
| `--boot-args` | No | Kernel boot arguments (see below) |
| `--mem-size` | No | Memory in MiB (default: 128) |
| `--vcpu` | No | Number of vCPUs (default: 1) |
| `--max-vcpu` | No | Max vCPUs, **must be ¡Ý `--vcpu`** (default: 1) |
| `--virnets` | No | Virtio-net device config as JSON array |
| `--serial-path` | No | Serial output path (default: `stdio`) |
| `--log-file` | No | Log file path (default: `dbs-cli.log`) |
| `--log-level` | No | Log level (default: `Debug`) |
| `--api-sock-path` | No | Unix socket for runtime API (global option, must be placed **before** `create`) |

### Recommended Boot Arguments

```
console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ip=<guest_ip>::<gateway_ip>:<netmask>::eth0:off
```

| Argument | Purpose |
|---|---|
| `console=ttyS0` | Direct kernel console to serial port |
| `reboot=k` | Use keyboard controller reset (required for MicroVMs without ACPI) |
| `panic=1` | Auto-reboot 1 second after kernel panic |
| `pci=off` | Disable PCI bus scanning (Dragonball uses MMIO) |
| `root=/dev/vda` | Root device via virtio-blk (use `vda1` if image has a partition table) |
| `ip=...` | Static network config via kernel parameter, avoiding DHCP overhead |

### IP Kernel Parameter Format

```
ip=<client-ip>:<server-ip>:<gateway-ip>:<netmask>:<hostname>:<device>:<autoconf>
```

Example for a `/30` P2P subnet:
```
ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off
```

## 5. Using the API Socket

To enable runtime management (e.g., hot-plugging devices), pass `--api-sock-path` as a **global** option (before the `create` subcommand):

```bash
sudo dbs-cli --api-sock-path /tmp/dragonball.sock create \
    --kernel-path /path/to/vmlinux \
    --rootfs /path/to/rootfs.img \
    ...
```

Then use `dbs-cli update` to modify the running VM:

```bash
sudo dbs-cli --api-sock-path /tmp/dragonball.sock update \
    --vcpu-resize 4
```

## 6. SSH Access to the VM

After the VM boots, connect via SSH using the key generated during rootfs creation:

```bash
ssh -i /path/to/id_rsa root@172.16.0.2
```

### Troubleshooting SSH Issues

If you encounter `Permission denied` errors (common with newer OpenSSH versions):

1. **Fix permissions** (inside VM console):
   ```bash
   chmod 700 /root/.ssh
   chmod 600 /root/.ssh/authorized_keys
   ```

2. **Allow legacy key types** (if using RSA keys with OpenSSH ¡Ý 8.8):
   ```bash
   echo "PubkeyAcceptedKeyTypes +ssh-rsa" >> /etc/ssh/sshd_config
   echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
   systemctl restart ssh
   ```

## 7. Common Issues

| Issue | Cause | Solution |
|---|---|---|
| `--max-vcpu` panic | `max-vcpu` < `vcpu` | Always set `--max-vcpu` ¡Ý `--vcpu` |
| `root=/dev/vda` fails | Image has partition table | Use `root=/dev/vda1` instead |
| No network in VM | TAP not configured on host | Run host network setup commands (Section 3) |
| `avc: denied` logs | SELinux in permissive mode | Safe to ignore; no functional impact |
| SSH key rejected | OpenSSH version mismatch | Use `ed25519` keys or add `PubkeyAcceptedKeyTypes +ssh-rsa` |
| `api-sock-path` error | Placed after `create` | Must be a **global** option, placed **before** the subcommand |
