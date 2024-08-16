#ifndef RULE_H
#define RULE_H

#include <stdint.h>
#include <unistd.h>
#include "cora.h"

struct fast_p {
	char* fp;
	uint32_t idx;
};

struct rule_t {
    ssize_t n_contents;     // number of elements in the array
    uint32_t sid;           // rule signature id
    //struct ac_root dfa;
	struct node_array* dfa;
};

#endif

