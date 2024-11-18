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

struct xdp_program * prog;

static void int_exit(int sig)
{
        xdp_program__close(prog);
        exit(0);
}

int main ()
{
        prog = xdp_program__open_file ("xdp_drop.o", "FODASE", 0);
        if (!prog)
        {
                printf ("xdp_program__open_file error");
                return 1;
        }

        int ifindex = 2;

        int ret = xdp_program__attach (prog, ifindex, XDP_MODE_SKB, 0);
        if (ret) {
                printf ("xdp_program__attach error");
                return ret;
        }

        struct bpf_object *bpf_obj = xdp_program__bpf_obj (prog);
        int map_fd = bpf_object__find_map_fd_by_name (bpf_obj, "outer_map");
        if (map_fd < 0) {
                printf ("bpf_object__find_map_fd_by_name error");
                return map_fd;
        }

        
        int new_map_fd = bpf_map_create (BPF_MAP_TYPE_ARRAY, "inner_map_name", sizeof(__u32), sizeof(__u32), 1000, 0);
        printf ("new_map_fd: %d\n", new_map_fd);

        
        int value = 8;

        int index = 0;
        bpf_map_update_elem (new_map_fd, &index, &value, BPF_ANY);
        if (new_map_fd < 0){
                printf ("deu merda aqui ta?");
                exit (1);
        }
        index = 0;
        ret = bpf_map_update_elem (map_fd, &index, &new_map_fd, BPF_ANY);
        
        printf ("ret: %lld\n", ret);



        /*
        int map_value_ptr;
        int key = 0;
        sleep (5);
        bpf_map_lookup_elem (map_fd, &key, &map_value_ptr);

        printf ("map_value_ptr: %llx\n", map_value_ptr);

        ret = bpf_map_create (BPF_MAP_TYPE_ARRAY, "james_second_map", sizeof(int), sizeof(int), 1, 0);

        printf ("ret: %d\n", ret);





        
        signal(SIGINT, int_exit);
        signal(SIGTERM, int_exit);
        
        printf ("done %d", getpid());
        getchar();
        */
        return 0;

}
