/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include <bpf/bpf_core_read.h> /* bpf_core_type_id_local */

#include "xdp/parsing_helpers.h"
#include "af_xdp_kern_shared.h"

#include "common_kern_user.h"

#define PORT_RANGE 65536
#define IDS_INSPECT_MAP_SIZE 65536
#define IDS_INSPECT_DEPTH 1520  // MTU 1500 bytes
#define IDS_INSPECT_STRIDE 1
#define TAIL_CALL_MAP_SIZE 2

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} perf_event_map SEC(".maps");

struct xdp_hints_mark {
	__u32 mark;
    __u32 global_map_index;
} __attribute__((aligned(4)));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} counter_map SEC(".maps");

SEC("xdp")
int xdp_inspect_payload(struct xdp_md *ctx)
{

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 sample_size = (__u16)(data_end - data);

    /* Compute current packet pointer */

    struct perf_event_sample pes;
    __builtin_memset(&pes, 0, sizeof(pes));

    pes.pkt_len = sample_size;

    /* The XDP perf_event_output handler will use the upper 32 bits
     * of the flags argument as a number of bytes to include of the
     * packet payload in the event data. If the size is too big, the
     * call to bpf_perf_event_output will fail and return -EFAULT. */
    flags |= (__u64)sample_size << 32;

    bpf_perf_event_output(ctx, &perf_event_map, flags, &pes, sizeof(pes));
    return XDP_DROP;

    /* The payload is not inspected completely (!!!!!!!!!!!!!!!!!!!!)*/
    return XDP_DROP;
}

SEC("xdp")
int xdp_ids_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 sample_size = (__u16)(data_end - data);

    /* Compute current packet pointer */

    struct perf_event_sample pes;
    __builtin_memset(&pes, 0, sizeof(pes));

    pes.pkt_len = sample_size;

    /* The XDP perf_event_output handler will use the upper 32 bits
     * of the flags argument as a number of bytes to include of the
     * packet payload in the event data. If the size is too big, the
     * call to bpf_perf_event_output will fail and return -EFAULT. */
    flags |= (__u64)sample_size << 32;

    bpf_perf_event_output(ctx, &perf_event_map, flags, &pes, sizeof(pes));
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
