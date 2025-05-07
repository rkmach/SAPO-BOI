#ifndef MAPS_H
#define MAPS_H

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_AF_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} counter_map SEC(".maps");

// os 4 primeiros campos foram registrados em seções BTF. Os últimos 3 são somente para tail call
struct xdp_hints_mark {
        __u32 mark;
        __u32 global_map_index;
        __u32 rule_index;
        __u32 btf_id;
} __attribute__((aligned(4))) __attribute__((packed));

#endif

