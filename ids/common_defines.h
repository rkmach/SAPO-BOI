#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <net/if.h>
#include <linux/types.h>
#include <stdbool.h>
#include <netinet/ether.h> /* struct ether_addr */

struct config {
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	bool do_unload;
	bool reuse_maps;
	char pin_dir[512];
	char filename[512];
	char progsec[32];
	__u16 xsk_bind_flags;
	int xsk_if_queue;
	bool xsk_wakeup_mode;
	
	char tail_call_map_name[32];
	int tail_call_map_entry_count;
	int tail_call_map_idx[32];
	char tail_call_map_progsec[32][32];

	char tcp_rule_inter[64];
	char udp_rule_inter[64];

	/* Real-Time scheduler setting */
	bool opt_busy_poll;
	__u32 batch_pkts;
};

#define BATCH_PKTS_MAX		64
#define BATCH_PKTS_DEFAULT	4

extern int verbose;

/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

#endif /* __COMMON_DEFINES_H */
