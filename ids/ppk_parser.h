#ifndef PPK_PARSER_H
#define PPK_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include "cora.h"

#define PPK_FAST_PAT  1 << 5
#define PPK_NOCASE  1 << 4
#define PPK_DEPTH  1 << 3
#define PPK_OFFSET  1 << 2
#define PPK_DISTANCE  1 << 1
#define PPK_WITHIN  1
#define PPK_BUF_SIZE 4096
#define PPK_LAST_PORT 65535

#define PPK_STATE_RNPORTS 0
#define PPK_STATE_RPORTS 1
#define PPK_STATE_RNRULES 2
#define PPK_STATE_RRULES 3 
#define PPK_STATE_RSID 4
#define PPK_STATE_RNCONTENTS 5
#define PPK_STATE_RCONTENTS 6
#define PPK_STATE_RNBYTES 7
#define PPK_STATE_RCONTENT 8
#define PPK_STATE_ROPTIONS 9
#define PPK_STATE_RRULEINDEX 10

#define PPK_PSPATE_ANYTHING 0 
#define PPK_PSTATE_RANGE 1

#define PPK_RANGE -1
#define PPK_NEG -2
#define PPK_ARRAY -3

#define PPK_LINE_SIZE 1024
#define PPK_STR_INT_SIZE 1024

struct ppk_content{
        uint8_t* pattern;
        int size_pattern;

        bool fast_pat;
        bool nocase;
        int depth;
        int offset;
        int distance;
        int within;
        off_t pos;
};

struct ppk_rule{
        uint32_t sid;
        int num_contents;
        struct ppk_content* contents;  // so por enquanto, depois colocar ponteiro p/ automato
        struct ahocora_trie *trie;
};

struct ppk_port_pair{
	int* src_port;
	int size_src_port;

	int* dst_port;
	int size_dst_port;

        int num_rules;
        struct ppk_rule** rules;

        struct ahocora_trie *fp_trie;
};


#endif
