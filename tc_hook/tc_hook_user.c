#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <net/if.h> // for if_nametoindex

#include <bpf/libbpf.h>

#define PROG_NAME "cls"
#define SEC_NAME "classifier"
#define IFNAME "eth0"

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;

    char filename[256];
    int ret, fd;
    bool clean_hook = false;

    /* open bpf object file */
    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "error opening BPF object file...\n");
        return 1;
    }

    fprintf(stdout, "open object file success\n");

    /* load bpf object */
    if (bpf_object__load(obj))
    {
        fprintf(stderr, "error load bpf object file: %s\n", strerror(errno));
        ret = -1;
        goto cleanup;
    }

    fprintf(stdout, "load object file success\n");

    /* find bpf program */
    prog = bpf_object__find_program_by_name(obj, PROG_NAME);
    // prog = bpf_object__find_program_by_title(obj, SEC_NAME);
    if (libbpf_get_error(prog))
    {
        fprintf(stderr, "error find " SEC_NAME " prog in obj file\n");
        ret = -1;
        goto cleanup;
    }

    fd = bpf_program__fd(prog);

    fprintf(stdout, "find matched prog from object file, fd is %d...\n", fd);

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
                        .ifindex = if_nametoindex(IFNAME),
                        .attach_point = BPF_TC_EGRESS);

    // May print "libbpf: Kernel error message: Exclusivity flag on, cannot modify"
    // if hook has already exist.
    // See https://www.spinics.net/lists/bpf/msg44838.html.

    /* tc qdisc add dev eth0 clsact */
    ret = bpf_tc_hook_create(&hook);
    if (ret == -EEXIST)
    {
        clean_hook = true;
    }
    else if (ret < 0)
    {
        fprintf(stderr, "error create tc hook\n");
        goto cleanup;
    }

    fprintf(stdout, "create tc hook success...\n");

    /* tc filter add dev eth0 egress bpf da obj tc_hook_user_kern.o sec classifier */
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = fd);
    ret = bpf_tc_attach(&hook, &opts);
    if (ret == -EEXIST)
    {
        fprintf(stderr, "enter replace logic\n");
        // use BPF_TC_F_REPLACE to replace it.
        opts.flags = BPF_TC_F_REPLACE;
        opts.prog_fd = fd;
        ret = bpf_tc_attach(&hook, &opts);
    }

    if (ret < 0)
    {
        fprintf(stderr, "error attach program to tc hook: %s\n", strerror(errno));
        goto cleanup2;
    }

    fprintf(stdout, "attach bpf prog to tc hook success...\n");

    // handle and priority must be set, use the auto allocated handle
    // and priority.
    /* tc filter get dev eth0 egress proto all handle 0x2 pref 49152 bpf */
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, info_opts,
                        .handle = opts.handle, .priority = opts.priority);
    ret = bpf_tc_query(&hook, &info_opts);
    if (ret == -ENOENT)
    {
        fprintf(stderr, "error query tc filters: %s", strerror(errno));
        goto cleanup3;
    }

    fprintf(stdout, "find object prog id: %u\n", info_opts.prog_id);

    // handle and priority must be specified, otherwise tc will create a new filter instead of
    // replacing the old one.
    /* tc filter replace dev eth0 egress handle 0x2 pref 49152 bpf da obj tc_hook_user_kern.o sec classifier */
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, rep_opts,
                        .flags = BPF_TC_F_REPLACE,
                        .handle = opts.handle,
                        .priority = opts.priority,
                        .prog_fd = fd);
    ret = bpf_tc_attach(&hook, &rep_opts);
    if (ret < 0)
    {
        fprintf(stderr, "error replace program to tc hook: %s\n", strerror(errno));
        goto cleanup2;
    }

    // pause here so that you can test it by `ping 10.10.10.10` and watch
    // the debug output by `sudo cat /sys/kernel/debug/tracing/trace_pipe`
    fprintf(stdout, "test and watch the output, enter any key to continue...");
    getchar();

    fprintf(stdout, "cleanup the resources...\n");

cleanup3:
    bpf_tc_detach(&hook, &opts);

cleanup2:
    if (clean_hook)
        bpf_tc_hook_destroy(&hook);

cleanup:
    bpf_object__close(obj);
    return ret;
}