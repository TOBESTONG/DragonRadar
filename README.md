# DragonRadar - Kernel Fuzzer for Cloud-Native MicroVMs

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**DragonRadar** is a kernel fuzzing framework purpose-built for cloud-native MicroVM environments. It implements a dedicated virtualization adapter layer for [Dragonball](https://github.com/kata-containers/kata-containers) (the built-in lightweight VMM of Kata Containers), enabling developers to seamlessly leverage the [Syzkaller](https://github.com/google/syzkaller) kernel fuzzing infrastructure to test custom kernels under realistic cloud-native operational scenarios.

## Key Features

- **Dragonball Adapter Layer**: A native `vm.impl` backend (`vm/dragonball`) that integrates the Dragonball MicroVM engine into Syzkaller's standard instance lifecycle (`Create → Run → Close`), supporting batch concurrent scheduling of hundreds of test instances.
- **Isolated Static Virtual Network Topology**: A stateless P2P subnet allocation algorithm using the `169.254.0.0/16` link-local address space. Each instance is assigned a dedicated `/30` subnet with pre-computed host gateway IP, guest IP, and MAC address, eliminating DHCP overhead and broadcast storms in high-concurrency startup scenarios.

## Architecture

```
syz-manager (Host)
    │
    ├── Pool.Create() ──► dbs-cli create ──► Dragonball VM
    │                                           │
    │   ┌── SSH Stdout ──────────────────────┐  │
    │   │── Serial Console (Unix Socket) ────┤  │
    │   └──────► OutputMerger (Crash Detect) ─► Manager
    │
    └── Static P2P Network: 169.254.x.1 ◄──► 169.254.x.2
```

## Documentation

- [How to install DragonRadar](docs/setup.md)
- [How to use DragonRadar](docs/usage.md)
- [How to boot Dragonball (dbs-cli)](docs/linux/how_to_use_dbs_cli.md)
- [How Syzkaller works (internals)](docs/internals.md)
- [Configuration reference](docs/configuration.md)

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/TOBESTONG/DragonRadar.git
cd DragonRadar

# 2. Build syzkaller binaries
make

# 3. Prepare a Dragonball-compatible kernel and minimal rootfs
#    (see docs for detailed instructions)

# 4. Create a config file (see example below)
# 5. Run the fuzzer
./bin/syz-manager -config dragonradar.cfg
```

### Example Configuration (`dragonradar.cfg`)

```json
{
    "target": "linux/amd64",
    "http": "127.0.0.1:58001",
    "workdir": "/path/to/workdir",
    "kernel_obj": "/path/to/kernel/linux-src",
    "image": "/path/to/rootfs/alpine.img",
    "sshkey": "/path/to/rootfs/id_rsa",
    "syzkaller": "/path/to/DragonRadar",
    "procs": 2,
    "type": "dragonball",
    "cover_filter": {},
    "raw_cover": false,
    "reproduce": false,
    "vm": {
        "count": 2,
        "kernel_path": "/path/to/kernel/linux-src/vmlinux",
        "rootfs": "/path/to/rootfs/alpine.img",
        "boot_args": "panic=1 console=ttyS0 root=/dev/vda rw",
        "mem": 2048,
        "cpu": 2,
        "net_prefix": "169.254",
        "tap_prefix": "db1_",
        "dbs_cli": "/path/to/dbs-cli/target/release/dbs-cli"
    }
}
```

| Field | Description |
|---|---|
| `target` | Target OS and architecture (e.g., `linux/amd64`) |
| `workdir` | Working directory for fuzzer state and crash artifacts |
| `kernel_obj` | Path to the compiled kernel source tree (for symbol resolution) |
| `image` / `vm.rootfs` | Path to the minimal rootfs image |
| `sshkey` | Path to the SSH private key for VM access |
| `type` | Must be `"dragonball"` to use the Dragonball adapter |
| `vm.kernel_path` | Path to the `vmlinux` binary for Direct Kernel Boot |
| `vm.dbs_cli` | Path to the `dbs-cli` binary |
| `vm.count` | Number of concurrent VM instances |
| `vm.mem` / `vm.cpu` | Memory (MB) and vCPU count per instance |
| `vm.net_prefix` | Link-local subnet prefix for P2P networking (e.g., `169.254`) |
| `vm.tap_prefix` | TAP device name prefix (e.g., `db1_`) |
| `vm.boot_args` | Extra kernel boot arguments |

## Credits

DragonRadar is built on top of [Syzkaller](https://github.com/google/syzkaller) by Google. The Dragonball adapter layer, static network topology algorithm, and minimal rootfs design are developed as part of this project.

## Disclaimer

This is not an official Google product. The Syzkaller base code is licensed under Apache 2.0.
