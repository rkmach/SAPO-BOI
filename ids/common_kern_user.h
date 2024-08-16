/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#define MAX_AF_SOCKS    64
#include<stdint.h>

/* Alias for TCP / UDP ports */
typedef __u16 src_port_t;
typedef __u16 dst_port_t;

struct port_map_key {
	src_port_t src_port;
	dst_port_t dst_port;
};

/* Key-Value of ids_inspect_map */
struct automaton_map_key {
	__u16 state;
	__u8 transition;
	__u8 padding;  /* this padding is mandatory because values must be 32-bit sized when using BPF_MAP_TYPE_ARRAY */
};

struct automaton_map_value {
	__u16 state;
	__u16 leaf;
	int16_t fp__rule_index;
};

struct automaton_map_update_value {
	struct automaton_map_value value;
	uint8_t padding[8 - sizeof(struct automaton_map_value)];
};

#endif /* __COMMON_KERN_USER_H */

