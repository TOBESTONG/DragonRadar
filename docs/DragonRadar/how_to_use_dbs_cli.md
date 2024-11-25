## dbs-cli Installation
Refer to [this link](https://github.com/openanolis/dbs-cli) for details.

Clone the repository:

```bash
git clone https://github.com/openanolis/dbs-cli.git
cd /path/to/dbs-cli
cargo build --all-features
```

Below is an example of using `dbs-cli` to start a Dragonball VM:

```bash
cd /path/to/dbs-cli/target/debug
sudo ./dbs-cli create \
    --log-file dbs-cli.log --log-level ERROR \
    --kernel-path /path/to/kernel/vmlinux \
    --rootfs /path/to/rootfs.img \
    --boot-args "console=ttyS0 console=ttyS1 earlyprintk=ttyS1 tty0 reboot=k debug panic=1 pci=off root=/dev/vda" \
    --mem-size 1024 \
    --vcpu 4 \
    --max-vcpu 4
```

## Kernel Preparation

Clone the Linux kernel repository:

```bash
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git linux-dbs
git checkout v5.10
cd /home/wbz/source/kernel/linux-dbs
make defconfig
make kvm_guest.config
/path/to/scripts/./config_change_linux.sh /path/to/kernel/linux-dbs/.config
make olddefconfig
make -j`nproc`
```

## Rootfs Preparation

Install debootstrap:

```bash
sudo apt-get install debootstrap
```

Navigate to the image directory:

```bash
cd /path/to/image
```

Download the `create-image.sh` script:

```bash
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
chmod +x create-image.sh
./create-image.sh
```

After successful execution, the `/path/to/image` directory will contain the following files:
- `bullseye.id_rsa`
- `bullseye.id_rsa.pub`
- `bullseye.img`


## Network Setup

Refer to [this link](https://github.com/firecracker-microvm/firecracker/blob/main/docs/network-setup.md) for network setup details.

### Host Machine:

The host needs to create a TAP interface. Example:

```bash
sudo ip tuntap add dev tap0 mode tap 
sudo ip addr add 192.168.100.1/24 dev tap0
sudo ip link set tap0 up
```

Set up port forwarding rules:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 10021 -j DNAT --to-destination 10.0.2.15:22
sudo iptables -t nat -A POSTROUTING -j MASQUERADE
```

### Virtual Machine:

Dragonball's network configuration supports virtio-net, and requires the following parameters for startup:

```bash
--virnets '[{
    "guest_mac":"AA:BB:CC:DD:EE:FF",
    "backend":{
        "type":"virtio",
        "iface_id":"eth0",
        "host_dev_name":"tap0",
        "allow_duplicate_mac":true
    }
}]'
```

Once inside the VM, configure the network interface:

```bash
auto eth0
iface eth0 inet dhcp
ip addr add 192.168.100.2/24 dev eth0
ip link set eth0 up
```

Test SSH connection from the host machine:

```bash
ssh -i /path/to/image/bullseye.id_rsa root@192.168.100.2
```


