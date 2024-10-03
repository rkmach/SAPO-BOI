#ifndef PPK_PARSER_H
#define PPK_PARSER_H

#include<stdint.h>
#include<stdbool.h>
#include <errno.h>

#define PPK_FAST_PAT  1 << 5
#define PPK_NOCASE  1 << 4
#define PPK_DEPTH  1 << 3
#define PPK_OFFSET  1 << 2
#define PPK_DISTANCE  1 << 1
#define PPK_WITHIN  1
#define PPK_BUF_SIZE 4096

#define PPK_STATE_RPORTS 0
#define PPK_STATE_RNRULES 1
#define PPK_STATE_RRULES 2 
#define PPK_STATE_RSID 3
#define PPK_STATE_RNCONTENTS 4
#define PPK_STATE_RCONTENTS 5
#define PPK_STATE_RNBYTES 6
#define PPK_STATE_RCONTENT 7
#define PPK_STATE_ROPTIONS 8

#define PPK_LINE_SIZE 1024
#define PPK_STR_INT_SIZE 10

//#define PPK_ERR (a) do{printf ("ERROR: %s: %s", stra (a), __func__, ##__VA_ARGS__),exit (a)}while(0)
//define PPK_ERR(a, ...) printf("%s(): " a, __func__, ##__VA_ARGS__)

struct ppk_content{
        char* pattern;
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
};

struct ppk_port_pair{
	int* src_port;
	int size_src_port;

	int* dst_port;
	int size_dst_port;

        int num_rules;
        struct ppk_rule* rules;
};


#endif
