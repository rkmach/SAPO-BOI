#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "cora.h"

struct {
        __uint (type, BPF_MAP_TYPE_ARRAY);
        __type (key, int);
        __type (value, struct ahocora_static_trie);
        __uint (max_entries, 1);
} james_map SEC (".maps");

SEC ("FODASE")
int xdp_drop_prog (struct xdp_md *ctx)
{
        static const char fmt[] = "JAMES-%d";
        int key = 0;
        struct ahocora_static_trie *value = bpf_map_lookup_elem (&james_map, &key);
        struct ahocora_node* node;
        int* ptr;
        if(value){
                if(value->array){
                        node = value->array;
                        if(node->basic_links){
                                ptr = &(node->basic_links) + 97;
                                if(ptr){
                                        bpf_trace_printk (fmt, sizeof(fmt), *ptr);
                                }
                        }
                }
        }
        /*
        struct ahocora_static_trie trie;
        trie.num_patterns = 21;
        if (value)
                *value = trie;
        else
                bpf_trace_printk (fmt,7);
        */
                
        return XDP_DROP;
}

char _license [] SEC ("license") = "GPL";
