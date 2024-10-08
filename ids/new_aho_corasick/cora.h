#ifndef CORA_H
#define CORA_H

#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#define NUM_ACCEPTABLE_SYMBOLS 256
#define AC_AUTOMATON_SIZE 10000

struct ahocora_node {
        int id;
        int basic_links[NUM_ACCEPTABLE_SYMBOLS];
        int suffix_link;
        int dict_suffix_link;
        bool leaf;
        bool hit;
        int rule_sid;
};

struct ahocora_trie {
        struct node **array;
        ssize_t size;
};


struct ahocora_trie* ahocora_init_trie ();
int ahocora_insert_pattern (struct ahocora_trie *, char *pattern);
int ahocora_search (struct ahocora_trie *, char *input);
#endif
