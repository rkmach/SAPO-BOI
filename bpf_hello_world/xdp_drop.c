#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct inner_map {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1000);
        __type(key, __u32);
        __type(value, __u32);
        //__uint(map_flags, BPF_F_NO_PREALLOC);
}james SEC (".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
        __uint(max_entries, 10);
        __type(key, __u32);
        __array(values, struct inner_map);
} outer_map SEC (".maps");


static __always_inline void port_intersection (int *src, int src_size, int *dst, int dst_size, int *ret, int *ret_size)
{
        int *largest;
        int largest_size;
        int *smaller;
        int smaller_size;
        *ret_size = 0;
        if (src_size > dst_size){
                largest = src;
                largest_size = src_size;
                smaller = dst;
                smaller_size = dst_size;
        }
        else {
                largest = dst;
                largest_size = dst_size;
                smaller = src;
                smaller_size = src_size;
        }

        int cur_port;
        for (int i = 0 ; i < largest_size ; i++) {
                cur_port = largest[i];
                for (int j = 0 ; j < smaller_size ; j++){
                        if (smaller[j] == cur_port){
                                ret[*ret_size] = cur_port;
                                (*ret_size)++;
                                break;
                        }
                }
        }

}

SEC ("FODASE")
int xdp_drop_prog (struct xdp_md *ctx)
{
        static const char fmt1[] = "JAMES1";
        static const char fmt2[] = "JAMES2";
        static const char fmt3[] = "JAMES3";
        static const char fmt4[] = "JAMES4";

        int a [10] = {1,2,3,4,5,6,7,8,9,10};
        int b [5] = {3,5,6,7,1};
        int ret [10] = {0};
        int ret_size = 10;
        port_intersection (a, 10, b, 5, ret, &ret_size);
        for (int i = 0 ; i < ret_size ; i++){
                bpf_trace_printk (fmt1, 7);
        }
        
        /*
        int i = 0;
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (; i < 8192 * 2; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int k
                ey = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        for (i = 0 ; i < 8192; i++){
                int key = 0;
                int *value = bpf_map_lookup_elem (&james, &key);
                if (!value)
                        return XDP_DROP;
                key = i + 1;
                *value = i;
        }
        */
        
        /*
        struct inner_map *outer = bpf_map_lookup_elem (&outer_map, &key);
        if (!outer){
                bpf_trace_printk (fmt4,7);
                return XDP_DROP;
        }

        key = 0;
        int *value = bpf_map_lookup_elem (outer, &key);
        if (value){
                if (*value == 0)
                        bpf_trace_printk (fmt1,7);
                else
                        bpf_trace_printk (fmt3,7);
        }
        else
                bpf_trace_printk (fmt2,7);
                
                */
        return XDP_DROP;
}

char _license [] SEC ("license") = "GPL";
