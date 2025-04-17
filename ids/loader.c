#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_link.h>
#include <signal.h>
#include <net/if.h>
#include <assert.h>

/* In this example we use libbpf-devel and libxdp-devel */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <sys/resource.h>

struct xdp_program * prog;

static void int_exit(int sig)
{
        xdp_program__close(prog);
        exit(0);
}

int main ()
{
        struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
        if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
                return -1;
        }
        prog = xdp_program__open_file ("af_xdp_kern.o", "xdp", 0);
        if (!prog)
        {
                printf ("xdp_program__open_file error");
                return 1;
        }

        int ifindex = 6;

        int ret = xdp_program__attach (prog, ifindex, XDP_MODE_SKB, 0);
        if (ret) {
                printf ("xdp_program__attach error");
                return ret;
        }

        struct bpf_object *bpf_obj = xdp_program__bpf_obj (prog);
        signal(SIGINT, int_exit);
        signal(SIGTERM, int_exit);
        
        printf ("done %d", getpid());
        return 0;

}
