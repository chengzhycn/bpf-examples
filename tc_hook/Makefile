CC := clang

KERN_SRC := tc_hook_kern.c
KERN_TAR := tc_hook_user_kern.o
KERN_CFLAGS = -O2 -g -target bpf
KERN_INCLUDE := -I../usr/include/

USER_SRC := tc_hook_user.c
USER_TAR := tc_hook_user
USER_CFLAGS = -O2
USER_LIBS := -lelf -lz -lbpf
USER_LD_LIBS := -L../usr/lib64/
USER_INCLUDE := -I../usr/include/

all: $(USER_TAR) $(KERN_TAR)


$(USER_TAR): $(USER_SRC)
	$(CC) $(USER_CFLAGS) $(USER_INCLUDE) $(USER_LD_LIBS) -o $(USER_TAR) $(USER_SRC) $(USER_LIBS)

$(KERN_TAR): $(KERN_SRC)
	$(CC) $(KERN_CFLAGS) $(KERN_INCLUDE) -o $(KERN_TAR) -c $(KERN_SRC)

.PHONY: clean
clean:
	rm -rf $(USER_TAR) $(KERN_TAR)
