#include <bpf/libbpf.h>

// must use cgroup v2
#define CG2_PATH "/sys/fs/cgroup/master1/slave01"

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
}