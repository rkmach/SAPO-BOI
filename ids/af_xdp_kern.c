#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h> /* bpf_core_type_id_local */
#include "xdp/parsing_helpers.h"
#include "common_kern_user.h"
#include "maps.h"

//#define MAX_MTU 1520  // MTU 1500 bytes

SEC("xdp")
int xdp_inspect_payload(struct xdp_md *ctx)
{
        __u32 rx_queue_index = ctx->rx_queue_index;
        return bpf_redirect_map(&xsks_map, rx_queue_index, 0);
}

SEC("xdp")
int xdp_ids_func(struct xdp_md *ctx)
{
        __u32 rx_queue_index = ctx->rx_queue_index;
        return bpf_redirect_map(&xsks_map, rx_queue_index, 0);
}

