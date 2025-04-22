#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h> /* bpf_core_type_id_local */
#include "xdp/parsing_helpers.h"
#include "common_kern_user.h"

#define MAX_MTU 1520  // MTU 1500 bytes
                      //

#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} time_map SEC(".maps");

SEC("xdp")
int xdp_ids_func(struct xdp_md *ctx)
{

    __u64 time = bpf_ktime_get_ns();

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u32 action = XDP_PASS; // Default action

    // Parse packet
    struct hdr_cursor nh;
    int eth_type = 0, ip_type = 0;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct tcphdr *tcph;


    nh.pos = data;
    eth_type = parse_ethhdr(&nh, data_end, &eth);

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iph);
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        ip_type = parse_ip6hdr(&nh, data_end, &ip6h);
    }
    else
        return XDP_PASS;

    void* end_ip = nh.pos; // aponta pro final do cabeçalho IP
    char* letter;
    char method[5];
    int delta;
    if (ip_type == IPPROTO_TCP) {
        if (parse_tcphdr(&nh, data_end, &tcph) > 0) {
            //bpf_trace_printk("num deu 1", 10);
                if (nh.pos + sizeof(tcph) > data_end){
                        return -1;
                }
                letter = nh.pos + 1;
                //bpf_printk("%c\n", *letter);
                //bpf_printk("%c\n", *(letter + 1));
                if (*letter == 'E' || *letter == 'O'){
                        method[0] = *((char*)nh.pos);
                        method[1] = *letter;
                        method[2] = *(letter + 1);
                        method[3] = *(letter + 2);
                        method[4] = '\0';
                        bpf_printk("%s\n", method);
                        char* new_content = (char*)end_ip;
                        if (new_content + sizeof(method) > data_end)
                                return -1;
                        #pragma unroll
                        for(int i = 0; i < sizeof(method); i++){
                                *(new_content + i) = *(method + i);
                        }
                        delta = data_end - (end_ip + 5);
                        bpf_printk("delta1 = %d\n", delta);
                        if(bpf_xdp_adjust_tail(ctx, 0-delta) < 0){
                                bpf_printk("Deu pau 1\n");
                                return -1;
                        }
                        time = bpf_ktime_get_ns() - time;
                        bpf_printk("time1 = %lld\n", time);
                }
                else{
                        // esse é o caso que não é HTTP
                        delta = data_end - end_ip;
                        if(bpf_xdp_adjust_tail(ctx, 0-delta) < 0){
                                bpf_printk("Deu pau 2.. delta = %d\n", delta);
                                return -1;
                        }
                        bpf_printk("delta2 = %d\n", delta);
                        time = bpf_ktime_get_ns() - time;
                        bpf_printk("time2 = %lld\n", time);
                }
        }
    }

    __u32 k = 0;
    __u64 *v;
    v = bpf_map_lookup_elem(&time_map, &k);
    if (v) {
        __sync_fetch_and_add(v, time);
        bpf_map_update_elem(&time_map, &k, v, BPF_ANY);
        bpf_printk("time = %d\n", *v);
    }
    return action;
}

char _license [] SEC ("license") = "GPL";

