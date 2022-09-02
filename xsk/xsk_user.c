#include <bpf/xsk.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static void __exit_with_error(int error, const char *file, const char *func,
                              int line) {
  fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func, line, error,
          strerror(error));
  exit(EXIT_FAILURE);
}

#define exit_with_error(error) \
  __exit_with_error(error, __FILE__, __func__, __LINE__)

/*
 * @struct xsk_ring_prod means producer ring.
 * @struct xsk_ring_cons means consumer ring.
 * Do not access the ring's member directly, use the API instead.
 */
struct xsk_umem_info {
  struct xsk_ring_prod fq;  // fill ring
  struct xsk_ring_cons cq;  // completion ring
  struct xsk_umem *umem;
  void *buffer;
};

struct xsk_socket_info {
  struct xsk_ring_prod rx;
  struct xsk_ring_cons tx;
  struct xsk_umem_info *umem;
  struxt xsk_socket *xsk;
}

int main(int argc, char **argv) {
  void *bufs;
  struct xsk_umem_info *umem;
  struct xsk_umem_config cfg;
  struct xsk_socket_info *xsk;
  struct xsk_socket_config xsk_config;
  int ret;

  cfg.fill_size = 4096;
  cfg.comp_size = 2048;
  cfg.frame_size = 4096;
  cfg.frame_headroom = 0;

  umem = calloc(1, sizeof(struct xsk_umem_info));
  if (!umem) exit_with_error(errno);

  bufs = mmap(NULL, 16 * 4096, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (bufs == MAP_FAILED) exit_with_error(errno);

  ret = xsk_umem__create(&umem->umem, bufs, 16 * 4096, &umem->fq, &umem->cq,
                         &cfg);
  if (ret) exit_with_error(-ret);

  umem->buffer = bufs;

  xsk->umem = umem;
  xsk_config.rx_size = 2048;
  xsk_config.tx_size = 2048;
  xsk_config.libbpf_flags = 0;
  xsk_config.xdp_flags = 0;
  xsk_config.bind_flags = 0;

  ret = xsk_socket__create(&xsk->xsk, "eth0", 0, umem->umem, &xsk->rx, &xsk->tx,
                           &xsk_config);
  if (ret) exit_with_error(-ret);

  return 0;
}