# tc_hook

An example for the libbpf new added low level TC-BPF managemnt API. More details see commit in libbpf or linux kernel:

[libbpf: Add low level TC-BPF management API](https://github.com/libbpf/libbpf/commit/d71ff87a2dd7b92787719aab233767e9c74fbd48)

## Build

```bash
make
```

## Test

* Terminal1:

```bash
sudo ./tc_hook_user
```

* Terminal2:

```bash
ping 10.10.10.10
```

* Terminal3:

```bash
sudo cat /sys/kernel/debug/tracing/trace-pipe
```

* output

```
           <...>-1342247 [000] .... 1327195.111866: 0: send packets to 10.10.10.10
           <...>-1342247 [000] .... 1327196.119067: 0: send packets to 10.10.10.10
           <...>-1342247 [000] .... 1327197.143079: 0: send packets to 10.10.10.10
           <...>-1342247 [000] .... 1327198.167082: 0: send packets to 10.10.10.10
```

## Notice

If you use tc command to load this `tc_hook_user_kern.o`, you will get following output:

```
BTF debug data section '.BTF' rejected: Invalid argument (22)!
```

The reason for this is that we are using iproute2 to attach an eBPF program, we will get the BTF errors. See https://www.spinics.net/lists/netdev/msg584085.html. Wait iproute2 to fix it.
