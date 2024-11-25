# How to use DragonRadar

## Prerequisites

Before officially using DragonRadar, we recommend that users first familiarize themselves with the usage of dbs-cli. Please refer to the documentation [how_to_use_dbs-cli.md](docs/DragonRadar/how_to_use_dbs_cli.md).
 

## Configuration

To use DragonRadar, you need to set up a configuration file. Below is an example of a configuration file:

```json
{
    "target": "linux/amd64",
    "http": "127.0.0.1:58889",
    "workdir": "/path/to/workdir",
    "kernel_obj": "/path/to/kernel",
    "image": "/path/to/image.img",
    "sshkey": "/path/to/sshkey",
    "syzkaller": "/path/to/syzkaller",
    "procs": 2,
    "type": "dragonball",
    "vm": {
        "count": 1,
        "kernel_path": "/path/to/kernel/vmlinux",
        "rootfs": "/path/to/rootfs.img",
        "boot_args": "console=ttyS0 console=ttyS1 earlyprintk=ttyS1 tty0 reboot=k debug panic=1 pci=off",
        "mem_size": 2048,
        "vcpu": 2,
        "max_vcpu": 2,
        "log_file": "/path/to/logfile.log",
        "log_level": "",
        "dbs_cli": "/path/to/dbs-cli",
        "dbs_args": "",
        "bridge_name": "",
        "bridge_ip": "192.168.200.1/24"
    }
}
```

## Running

Start the `syz-manager` process as:

```bash
./bin/syz-manager -config /path/to/config/syzkaller.cfg
```

The `syz-manager` process will wind up VMs and start fuzzing in them. The `-config` command-line option specifies the location of the configuration file, which is described in the Configuration section. Found crashes, statistics, and other information are exposed on the HTTP address specified in the manager config.

## Crashes

Once syzkaller detects a kernel crash in one of the VMs, it will automatically start the process of reproducing this crash (unless you specified `"reproduce": false` in the config). By default, it will use 4 VMs to reproduce the crash and then minimize the program that caused it. This may stop the fuzzing, since all of the VMs might be busy reproducing detected crashes.

The process of reproducing one crash may take from a few minutes up to an hour, depending on whether the crash is easily reproducible or not. Since this process is not perfect, you can try to manually reproduce the crash as described [here](reproducing_crashes.md).

If a reproducer is successfully found, it can be generated in one of two forms: syzkaller program or C program. Syzkaller always tries to generate a more user-friendly C reproducer, but sometimes fails for various reasons (e.g., slightly different timings). In case syzkaller only generates a syzkaller program, there's [a way to execute them](reproducing_crashes.md) to reproduce and debug the crash manually.

### Reproducing Crashes

- **Automatic Reproduction**: Syzkaller attempts to automatically reproduce crashes.
- **Manual Reproduction**: Follow the instructions provided [here](reproducing_crashes.md) for manual reproduction.

## Hub

If you're running multiple `syz-manager` instances, you can connect them together to allow program and reproducer exchange. See the details [here](hub.md).

