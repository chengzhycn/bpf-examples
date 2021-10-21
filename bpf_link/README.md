# bpf_link

The introduction of bpf_link was written in its initial commit messages. See https://www.spinics.net/lists/netdev/msg582043.html.

> bpf_link is and abstraction of an association of a BPF program and one
> of many possible BPF attachment points (hooks). This allows to have
> uniform interface for detaching BPF programs regardless of the nature of
> link and how it was created. Details of creation and setting up of
> a specific bpf_link is handled by corresponding attachment methods
> (bpf_program__attach_xxx) added in subsequent commits. Once successfully
> created, bpf_link has to be eventually destroyed with
> bpf_link__destroy(), at which point BPF program is disassociated from
> a hook and all the relevant resources are freed.

It comes from an idea by Daniel Borkmann(https://lore.kernel.org/bpf/a7780057-1d70-9ace-960b-ff65867dc277@iogearbox.net/), which simplifies the users destroy action and doesn't need to care how the resources created:

> I do like that we facilitate usage by adding these APIs to libbpf, but my $0.02
> would be that they should be designed slightly different. See it as a nit, but
> given it's exposed in libbpf.map and therefore immutable in future it's worth
> considering; right now with this set here you have:
> 
> int bpf_program__attach_kprobe(struct bpf_program *prog, bool retprobe,
> 			       const char *func_name)
> int bpf_program__attach_uprobe(struct bpf_program *prog, bool retprobe,
> 			       pid_t pid, const char *binary_path,
> 			       size_t func_offset)
> int bpf_program__attach_tracepoint(struct bpf_program *prog,
> 				   const char *tp_category,
> 				   const char *tp_name)
> int bpf_program__attach_raw_tracepoint(struct bpf_program *prog,
> 				       const char *tp_name)
> int bpf_program__attach_perf_event(struct bpf_program *prog, int pfd)
> int libbpf_perf_event_disable_and_close(int pfd)
> 
> So the idea is that all the bpf_program__attach_*() APIs return an fd that you
> can later on pass into libbpf_perf_event_disable_and_close(). I think there is
> a bit of a disconnect in that the bpf_program__attach_*() APIs try to do too
> many things at once. For example, the bpf_program__attach_raw_tracepoint() fd
> has nothing to do with perf, so passing to libbpf_perf_event_disable_and_close()
> kind of works, but is hacky since there's no PERF_EVENT_IOC_DISABLE for it so this
> would always error if a user cares to check the return code. In the kernel, we
> use anon inode for this kind of object. Also, if a user tries to add more than
> one program to the same event, we need to recreate a new event fd every time.
> 
> What this boils down to is that this should get a proper abstraction, e.g. as
> in struct libbpf_event which holds the event object. There should be helper
> functions like libbpf_event_create_{kprobe,uprobe,tracepoint,raw_tracepoint} returning
> such an struct libbpf_event object on success, and a single libbpf_event_destroy()
> that does the event specific teardown. bpf_program__attach_event() can then take
> care of only attaching the program to it. Having an object for this is also more
> extensible than just a fd number. Nice thing is that this can also be completely
> internal to libbpf.c as with struct bpf_program and other abstractions where we
> don't expose the internals in the public header.
> 
> Thanks,
> Daniel

## lifetime



## related patches

* https://lwn.net/ml/netdev/20200424053505.4111226-1-andriin@fb.com/
* 

## APIs

```bash
❯ ag bpf_link src/libbpf.map
170:            bpf_link__destroy;
215:            bpf_link__disconnect;
241:            bpf_link__fd;
242:            bpf_link__open;
243:            bpf_link__pin;
244:            bpf_link__pin_path;
245:            bpf_link__unpin;
246:            bpf_link__update_program;
247:            bpf_link_create;
248:            bpf_link_update;
262:            bpf_link_get_fd_by_id;
263:            bpf_link_get_next_id;
276:            bpf_link__detach;
277:            bpf_link_detach;
358:            bpf_linker__add_file;
359:            bpf_linker__finalize;
360:            bpf_linker__free;
361:            bpf_linker__new;
```