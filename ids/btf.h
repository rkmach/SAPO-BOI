#ifndef BTF_H
#define BTF_H

#define _GNU_SOURCE  /* Needed by sched_getcpu */
#include <sched.h>

#include <errno.h>
#include <bpf/libbpf.h>
#include "xsk_socket.h"
#include <bpf/btf.h> /* provided by libbpf */
#include "lib_xsk_extend.h"


/* This struct BTF mirrors kernel-side struct xdp_hints_mark */
struct xdp_hints_mark {
	__u32 btf_type_id; /* cached xsk_btf__btf_type_id(xbi) */
	struct xsk_btf_info *xbi;
	struct xsk_btf_member mark;
	struct xsk_btf_member global_map_index;
	struct xsk_btf_member rule_index;
};

struct xsk_btf_info *setup_btf_info(struct btf *btf, const char *struct_name);
int init_btf_info_via_bpf_object(struct bpf_object *bpf_obj, struct xdp_hints_mark* xdp_hints_mark);
bool is_tcp(uint8_t *pkt, struct xdp_hints_mark *meta, uint32_t* global_map_index, int16_t* rule_index);

#endif

