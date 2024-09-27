#ifndef PPK_PARSER_H
#define PPK_PARSER_H

#include<stdint.h>
#include<stdbool.h>

#define FAST_PAT  1 << 5
#define NOCASE  1 << 4
#define DEPTH  1 << 3
#define OFFSET  1 << 2
#define DISTANCE  1 << 1
#define WITHIN  1
#define BUF_SIZE 4096

#define PPK_STATE_RPORTS 0
#define PPK_STATE_RNRULES 1
#define PPK_STATE_RSID 2
#define PPK_STATE_RNCONTENTS 3
#define PPK_STATE_RCONTENTS 4
#define PPK_STATE_RBITMAP 5

#define PPK_LINE_SIZE 1024

struct ppk_content{
        char* pattern;
        ssize_t size_pattern;

        bool fast_pat;
        bool nocase;
        int depth;
        int offset;
        int distance;
        int within;
};

struct ppk_rule{
        uint32_t sid;
        ssize_t num_contents;
        struct ppk_content** contents;  // so por enquanto, depois colocar ponteiro p/ automato
};

struct ppk_port_pair{
	int* src_port;
	ssize_t size_src_port;

	int* dst_port;
	ssize_t size_dst_port;

        int num_rules;
        struct ppk_rule** rules;
};


#endif
