#ifndef CORA_H
#define CORA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define NUM_ACCEPTABLE_SYMBOLS 256
#define AC_AUTOMATON_SIZE 200000
#define MAX_FRAME_SIZE 1500

struct ahocora_node {
        int id;
        int basic_links[NUM_ACCEPTABLE_SYMBOLS];
        int suffix_link;
        int dict_suffix_link;
        int hit;
        int rule_sid;
        int parent;
        uint8_t suffix;
};

struct ahocora_trie {
        struct ahocora_node **array;
        ssize_t size;
        int num_patterns;
};


struct ahocora_trie* ahocora_create_trie ();
void ahocora_insert_pattern (struct ahocora_trie *, uint8_t *pattern,
                int pattern_len, int rule_id);
int ahocora_search (struct ahocora_trie *trie, uint8_t *input, int size);
void ahocora_build_suffix_links (struct ahocora_trie *trie);
void ahocora_build_dict_suffix_links (struct ahocora_trie *trie);
void ahocora_print_trie (struct ahocora_trie *trie);

#endif
