#ifndef AUTOMATON_H
#define AUTOMATON_H

#include "rule.h"

struct automaton_transition {
	uint16_t key_state;
	uint8_t key_transition;
	uint16_t value_state;
	uint16_t value_leaf;
	int16_t fp__rule_index;
};

struct automaton {
	size_t size;
	struct automaton_transition *entries;
};

struct port_group_t {
	uint16_t src_port;
	uint16_t dst_port;

	ssize_t n_rules;
	struct rule_t** rules;
	
	struct automaton* dfa;
	uint32_t global_map_index;  // isso aqui é o índice do dfa no mapa de dfas
};

struct protocol_port_groups_t {
	struct port_group_t** port_groups_array;
	ssize_t n_port_groups;
};

int build_automaton(struct fast_p* fast_patterns_array, size_t p_len, struct automaton *result);

#endif

