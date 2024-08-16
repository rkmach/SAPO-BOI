#ifndef CORA_H
#define CORA_H

#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#define S 128
#define IX_SIZE 1000
#define AC_AUTOMATON_SIZE 10000

#define TO_I(c) (c - ' ')
#define TO_C(i) (i + ' ')

struct node {
	int p, pc, depth, lnk, out, occ;
	bool leaf;
	int nxt[S], go[S], *ix;
	ssize_t ix_size;
	char* represents;
};

struct node_array {
	struct node** array;
	ssize_t array_size;
};

struct vetor_e_tamanho {
	int* array;
	ssize_t size;
};

struct node* init_node();
void insert_ix(struct node_array* array, int u, int ix);
void ins(struct node_array* aca, char* ne, int ix);
void mostra_estados(struct node_array* aca);
int go(struct node_array* aca, int u, int c);
int _link(struct node_array* aca, int u);
int out(struct node_array* aca, int u);
bool process(struct node_array* aca, char* hay);
struct node_array* get_ac_automaton();
void free_automaton(struct node_array* aca);

#endif

