#include <stdio.h>

#include <bpf/libbpf.h>

#define SEC_NAME "xxx"

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;

    char filename[256];
    int ret, fd;
    
    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "error opening BPF object file...\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "error loading bpf object file...\n");
        goto close_object;
    }

    prog = bpf_object__find_program_by_title(obj, SEC_NAME);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "error finding program " SEC_NAME " in obj file...\n");
        goto close_object;
    }

    /* all the bpf_program__attach_xxx functions will return a bpf_link object */
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "error attach program...\n");
        goto close_object;
    }

destroy_link:
    bpf_link__destroy(link);

close_object:
    bpf_object__close(obj);
}