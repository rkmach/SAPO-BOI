#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
        __uint (type, BPF_MAP_TYPE_ARRAY);
        __type (key, int);
        __type (value, int);
        __uint (max_entries, 1);
} james_map SEC (".maps");

SEC ("FODASE")
int xdp_drop_prog (struct xdp_md *ctx)
{
        static const char fmt[] = "JAMES2";
        int key = 0;
        int *value = bpf_map_lookup_elem (&james_map, &key);
        if (value)
                *value = 7;
        else
                bpf_trace_printk (fmt,7);
                
        return XDP_DROP;
}

char _license [] SEC ("license") = "GPL";
