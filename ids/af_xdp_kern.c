#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h> /* bpf_core_type_id_local */
#include "xdp/parsing_helpers.h"
#include "common_kern_user.h"
#include "maps.h"

#define N_PORT_PAIRS 1500
#define N_MAX_LINKS 487146
#define N_MAX_NODES 195322
#define N_PORT_SIZE 118
#define N_PORTS 65536
#define N_MAX_PORT_LIST 983
//#define N_UDP_PORT_SIZE 70

#define MAX_MTU 1520  // MTU 1500 bytes
struct link_key {
        int cur_state;
        uint8_t cur_byte;
};
struct port_pair {
        int src_port[N_PORT_SIZE];
        int src_port_size;

        int dst_port[N_PORT_SIZE];
        int dst_port_size;
};

struct basic_link_entry{
        int new_state;
        int sid;
};

struct suffix_link_entry {
        int next_state;
        int sid;
};


struct dict_suffix_links {
        __uint (type, BPF_MAP_TYPE_HASH);
        __uint (max_entries, N_MAX_NODES);
        __type (key, int);
        __type (value, int);
        __uint(map_flags, BPF_F_NO_PREALLOC);
};

struct suffix_link_table {
        __uint (type, BPF_MAP_TYPE_HASH);
        __uint (max_entries, N_MAX_NODES);
        __type (key, int);
        __type (value, struct suffix_link_entry);
        __uint(map_flags, BPF_F_NO_PREALLOC);
};

struct basic_link_table {
        __uint (type, BPF_MAP_TYPE_HASH);
        __uint (max_entries, N_MAX_LINKS);
        __type (key, struct link_key);
        __type (value, struct basic_link_entry);
        __uint(map_flags, BPF_F_NO_PREALLOC);
};

struct {
        __uint (type, BPF_MAP_TYPE_HASH_OF_MAPS);
        __uint (max_entries, N_PORT_PAIRS);
        __type (key, struct port_pair);
        __type (value, struct basic_link_table);
        __uint(map_flags, BPF_F_NO_PREALLOC);
}port_pair_table SEC (".maps");
        
struct port_list {
        __uint (type, BPF_MAP_TYPE_HASH);
        __uint (max_entries, N_MAX_PORT_LIST);
        __type (key, int);
        __type (value, int);
        __uint(map_flags, BPF_F_NO_PREALLOC);
};

struct {
        __uint (type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
        __uint (max_entries, N_PORTS);
        __type (key, int);
        __type (value, struct port_list);
}tcp_src_table SEC (".maps"), tcp_dst_table SEC (".maps"), udp_src_table SEC (".maps"), udp_dst_table SEC (".maps");

/*
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

static __always_inline int is_port_in_list (int port, int *list, int size)
{
        for (int i = 0 ; i < size ; i++){
                if (list[i] == port)
                        return true;
                if (list[i] > 0)
                        continue;
                //if (list[i] 

        }
}


SEC("xdp")
int xdp_inspect_payload(struct xdp_md *ctx)
{

    void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *data_meta = (void *)(long)ctx->data_meta;
	struct xdp_hints_mark *meta = data_meta;
	struct hdr_cursor nh;
    __u32 rx_queue_index = ctx->rx_queue_index;
	
	// Compute current packet pointer 

	if (meta + 1 > data) {
		return XDP_ABORTED;
	}

    __u32 mark;
    if(meta->mark == 1){  // is TCP?
        mark = 54;
    }
    else{
        mark = 42;
    }
    // bpf_printk("mark = %d\n", mark);

	nh.pos = data;

    if (nh.pos + mark > data_end)
        return XDP_DROP;
    nh.pos += mark;

    __u8 *transition;
    struct automaton_map_key map_key;
    struct automaton_map_value *map_value;
    int i;

    __u32 global_map_index = meta->global_map_index;
    struct ids_map* ids_inspect_map = bpf_map_lookup_elem(&global_map, &global_map_index);
    if(!ids_inspect_map)
        return XDP_DROP;

    map_key.state = 0;
    map_key.padding = 0;
    #pragma unroll
    for (i = 0; i < MAX_MTU; i++) {
        transition = nh.pos;
        if (transition + 1 > data_end) {
            // Reach the last byte of the packet (None fast pattern was found. Drop packet) 
            return XDP_DROP;
        }
        map_key.transition = *transition;
        map_value = bpf_map_lookup_elem(ids_inspect_map, &map_key);
        if (map_value) {
            map_key.state = map_value->state;
            if (map_value->leaf > 0) {
                meta->rule_index = map_value->fp__rule_index;
                meta->btf_id = bpf_core_type_id_local(struct xdp_hints_mark);

                return bpf_redirect_map(&xsks_map, rx_queue_index, 0);
            }
        }
		else map_key.state = 0;
        nh.pos += 1;
    }
    return XDP_DROP;
}

SEC("xdp")
int xdp_ids_func(struct xdp_md *ctx)
{

    __u32 k = 0, *v;
    v = bpf_map_lookup_elem(&counter_map, &k);
    if (v) {
        __sync_fetch_and_add(v, 1);
        bpf_map_update_elem(&counter_map, &k, v, BPF_ANY);
        bpf_printk("cont = %d\n", *v);
    }


    struct xdp_hints_mark *meta;
    int err;
    // Reserve space in-front of data pointer for our meta info 
	err = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));

	if (err)
		return XDP_DROP;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    meta = (void *)(unsigned long)ctx->data_meta;
    if (meta + 1 > data) // Verify meta area is accessible 
        return XDP_DROP;

    __u32 action = XDP_PASS; // Default action

    // Parse packet
    struct hdr_cursor nh;
    int eth_type, ip_type;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct udphdr *udph;
    struct tcphdr *tcph;
    int is_tcp = 0;
    src_port_t pkt_src_port;

    // __u16 src_port, dst_port;
    struct port_map_key port_map_key;
    __u32* port_map_value = NULL;

    nh.pos = data;
    eth_type = parse_ethhdr(&nh, data_end, &eth);

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iph);
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        ip_type = parse_ip6hdr(&nh, data_end, &ip6h);
    } else {
        goto out;
    }

    if (ip_type == IPPROTO_TCP) {
        if (parse_tcphdr(&nh, data_end, &tcph) < 0) {
            action = XDP_ABORTED;
            goto out;
        }
        is_tcp = 1;
        port_map_key.src_port = bpf_ntohs(tcph->source);
        port_map_key.dst_port = bpf_ntohs(tcph->dest);

        // se não houver chave no mapa para esse par de portas, nem precisa processar o pacote

        // Primeiro, testa com as portas que estão no pacote
        port_map_value = bpf_map_lookup_elem(&tcp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (sport, dport) (do pacote)
            goto pg_found;
        
        pkt_src_port = port_map_key.src_port;

        // se não achei, vou procurar por (any, dport)
        port_map_key.src_port = 0;
        port_map_value = bpf_map_lookup_elem(&tcp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (any, dport)
            goto pg_found;

        // se não achei, vou procurar por (sport, any)
        port_map_key.src_port = pkt_src_port;
        port_map_key.dst_port = 0;
        port_map_value = bpf_map_lookup_elem(&tcp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (sport, any)
            goto pg_found;

        // se não achei, vou procurar por (any, any)
        port_map_key.src_port = 0;
        port_map_key.dst_port = 0;
        port_map_value = bpf_map_lookup_elem(&tcp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (any, any)
            goto pg_found;

        if(!port_map_value)
            return XDP_DROP;

    } else if (ip_type == IPPROTO_UDP) {
        if (parse_udphdr(&nh, data_end, &udph) < 0) {
            action = XDP_ABORTED;
            goto out;
        }
        port_map_key.src_port = bpf_ntohs(udph->source);
        port_map_key.dst_port = bpf_ntohs(udph->dest);

        // se não houver chave no mapa para esse par de portas, nem precisa processar o pacote
        
        // Primeiro, testa com as portas que estão no pacote
        port_map_value = bpf_map_lookup_elem(&udp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (sport, dport) (do pacote)
            goto pg_found;
        
        pkt_src_port = port_map_key.src_port;
        // dst_port_t pkt_dst_port = port_map_key->dst_port;

        // se não achei, vou procurar por (any, dport)
        port_map_key.src_port = 0;
        port_map_value = bpf_map_lookup_elem(&udp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (any, dport)
            goto pg_found;

        // se não achei, vou procurar por (sport, any)
        port_map_key.src_port = pkt_src_port;
        port_map_key.dst_port = 0;
        port_map_value = bpf_map_lookup_elem(&udp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (sport, any)
            goto pg_found;

        // se não achei, vou procurar por (any, any)
        port_map_key.src_port = 0;
        port_map_key.dst_port = 0;
        port_map_value = bpf_map_lookup_elem(&udp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (any, any)
            goto pg_found;

        if(!port_map_value)
            return XDP_DROP;
    } 
    else {
            goto out;
    }
pg_found:
    // bpf_printk("port_map_value = %d", *port_map_value);
    // Only packet with valid TCP/UDP header and a valid port group will reach here 
    
    meta->global_map_index = *port_map_value;
    meta->mark = is_tcp;

    // Must use tail call, otherwise the instruction limit would be crossed.
    bpf_tail_call(ctx, &tail_call_map, 0);
    // The flow shoud had been deviated by the above line. If it was not, drop the packet
    action = XDP_DROP;

out:
    return action;
}


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 65536);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} tcp_src_port_map SEC(".maps");

SEC("xdp")
int xdp_ids_func(struct xdp_md *ctx)
{
        return XDP_PASS;
}
*/
