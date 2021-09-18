# bpf-examples

## Environments

* System: Ubuntu20.04 on Tencent Cloud
* Kernel: Linux VM-16-5-ubuntu 5.4.0-42-generic
* Iface: virtio_net-1.0.0

## Prerequisite

* [clang](https://github.com/llvm/llvm-project/releases)
* [libbpf](https://github.com/libbpf/libbpf) (a pre-build version has include in usr directory.)
* libz
* libelf

```bash
sudo apt install libelf-dev
```

## Examples

* tc_hook

## Q&A

* /usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found

> On x86_64 PC, the gcc-multilib debian package makes a symbol link at "/usr/include/asm" to "/usr/include/x86_64-linux-gnu". So you can install gcc-multilib package or just make this symbol link manually.
