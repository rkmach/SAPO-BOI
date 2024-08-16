#include "btf.h"
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

/*
#define NANOSEC_PER_SEC 1000000000  //10^9 
static uint64_t gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with clock_gettime! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}
*/

struct xsk_btf_info *setup_btf_info(struct btf *btf,
				    const char *struct_name)
{
	struct xsk_btf_info *xbi = NULL;
	int err;

	err = xsk_btf__init_xdp_hint(btf, struct_name, &xbi);
	if (err) {
		fprintf(stderr, "WARN(%d): Cannot BTF locate valid struct:%s\n",
			err, struct_name);
		return NULL;
	}
	return xbi;
}

int init_btf_info_via_bpf_object(struct bpf_object *bpf_obj, struct xdp_hints_mark* xdp_hints_mark)
{
	struct btf *btf = bpf_object__btf(bpf_obj);
	struct xsk_btf_info *xbi;

	xbi = setup_btf_info(btf, "xdp_hints_mark");
	if (xbi) {
		if (!xsk_btf__field_member("mark", xbi, &xdp_hints_mark->mark))
			return -EBADSLT;
		if (!xsk_btf__field_member("global_map_index", xbi, &xdp_hints_mark->global_map_index))
			return -EBADSLT;
		if (!xsk_btf__field_member("rule_index", xbi, &xdp_hints_mark->rule_index))
			return -EBADSLT;
		xdp_hints_mark->btf_type_id = xsk_btf__btf_type_id(xbi);
		xdp_hints_mark->xbi = xbi;
	}

	return 0;
}

bool is_tcp(uint8_t *pkt, struct xdp_hints_mark *meta, uint32_t* global_map_index, int16_t* rule_index){
    struct xsk_btf_info *xbi = meta->xbi;
	__u32 mark = 3;
	__u32 index = 99;
	__u32 r_index = 9;

	/* The 'mark' value is not updated in case of errors */
	XSK_BTF_READ_INTO(mark, &meta->mark, xbi, pkt);
	XSK_BTF_READ_INTO(index, &meta->global_map_index, xbi, pkt);
	XSK_BTF_READ_INTO(r_index, &meta->rule_index, xbi, pkt);
	*global_map_index = index;
	printf("rule_index = %d\n", r_index);
	*rule_index = r_index;
    if(mark == 1)
        return true;
    return false;
}

