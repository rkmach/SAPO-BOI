#include<stdio.h>
#include<stdint.h>

int main(int argc, char** argv){
        struct bpf_prog_info info = {};
        __u32 info_len = sizeof(info);
        struct bpf_object* bpf_obj = NULL;
        struct bpf_program *prog;
        struct bpf_map* map;
        bpf_obj = bpf_object__open_file("suspicion-xdp.o", NULL);
        if(!obj){
                puts("DEU PAU! -- Did not open object");
                return -1;
        }
        bpf_object__for_each_program(prog, obj){
                bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
                bpf_program__set_ifindex(prog, IFINDEX);
        }
        bpf_object__for_each_map(map, obj) {
                bpf_map__set_ifindex(map, IFINDEX);
        }
        bpf_object__for_each_map(map, obj) {
                int len, err, pinned_map_fd;
                char buf[64];

                len = snprintf(buf, 64, "%s/%s", "/sys/fs/bpf", bpf_map__name(map));
        }
}
