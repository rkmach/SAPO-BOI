#include<linux/bpf.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 65536);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} tcp_src_port_map SEC(".maps");

SEC("xdp")
int suspicion_module(struct xdp_md *ctx)
{
        return XDP_PASS;
}

