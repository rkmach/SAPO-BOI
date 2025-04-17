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

SEC("xdp")
int xdp_ids_func(struct xdp_md *ctx)
{

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

    void* end_ip = nh.pos; // aponta pro final do cabeçalho IP
    char* letter;
    char method[5];
    if (ip_type == IPPROTO_TCP) {
        if (parse_tcphdr(&nh, data_end, &tcph) > 0) {
            bpf_trace_printk("num deu 1", 10);
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
                }
        }
    }
    int delta = data_end - (end_ip + 5);
    bpf_xdp_adjust_tail(ctx, delta);
    //bpf_trace_printk("aaaaaaa", 8);
    *end_ip = method[0];
    *(end_ip + 1) = method[1];
    *(end_ip + 2) = method[2];
    *(end_ip + 3) = method[3];
    *(end_ip + 4) = method[4];
    bpf_printk("%s\n", *end_ip);



    return action;
}

char _license [] SEC ("license") = "GPL";

