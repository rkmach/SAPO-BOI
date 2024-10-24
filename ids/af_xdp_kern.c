#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h> /* bpf_core_type_id_local */
#include "xdp/parsing_helpers.h"
#include "common_kern_user.h"
#include "maps.h"


/*
struct susp_port_list{
        __uint (type, BPF_MAP_TYPE_ARRAY);
        __uint (max_entries, SUSP_MAX_LIST_ENTRIES);
        __uint (key_size, sizeof (int));
        __uint (value_size, sizeof (int));
} SEC (".maps");

struct susp_port_table {
        __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
        __uint(key_size, sizeof (int));
        __uint(max_entries, SUSP_MAX_PORTS);
        __array(values, struct susp_port_list);
} tcp_src_table SEC (".maps"), tcp_dst_table SEC (".maps"), udp_src_table SEC (".maps"), udp_dst_table SEC (".maps");

struct susp_fp_table {
        __uint (type, BPF_MAP_TYPE_ARRAY);
        __uint (max_entries, SUSP_MAX_LIST_ENTRIES);
        __uint (key_size, sizeof (int));
        __uint (value_size, sizeof (int));
};
*/
