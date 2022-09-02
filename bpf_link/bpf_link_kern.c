#include <linux/version.h>
#include <linux/ptrace.h>


SEC("kprobe/__x64_sys_write")
int bpf_prog(struct pt_regs *ctx) {
    
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;