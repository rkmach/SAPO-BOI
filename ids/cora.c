#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "cora.h"

struct node* init_node(){
	struct node *node;
	if (!(node = malloc(sizeof(struct node)))){
		puts("Não foi possível alocar memória para um nó");
		exit(-1);
	}
	node->p = 0;
	node->pc= 0;
	node->depth = -1;
	node->lnk = -1;
	node->out = -1;
	node->occ = 0;
	node->leaf = false;
	
	node->ix = NULL;
	node->ix_size = 0;

	for(int i = 0; i < S; i++){
		node->nxt[i] = -1;
		node->go[i] = -1;
	}

	node->represents = NULL;

	return node;
}

void insert_ix(struct node_array* array, int u, int ix){
	if (u >= array->array_size){
		puts("Deu merda porque u > tam. Essa posição já deveria ter sido criada");
		exit(-1);
	}

	// inicializando ix caso não exista
	if(!array->array[u]->ix){
		if(!(array->array[u]->ix = malloc(sizeof(int) * IX_SIZE))){
			puts("Não foi possível alocar memória para o ix de um nó");
			exit(-1);
		}
		array->array[u]->ix_size = 0;
	}

	array->array[u]->ix[array->array[u]->ix_size++] = ix;
}

void ins(struct node_array* aca, char* ne, int ix){
	int u = 0;
	for(int i = 0; i < strlen(ne); i++){
		int ch =  TO_I(ne[i]);
		if(aca->array[u]->nxt[ch] == -1) {  // significa que o caracter ainda não foi registrado
			aca->array[u]->nxt[ch] = aca->array_size;
			struct node* n = init_node();
			n->p = u;
			n->pc = ch;
			n->depth = i;
			aca->array[aca->array_size++] = n;
		}		
		u = aca->array[u]->nxt[ch];
	}
	aca->array[u]->leaf = true;
	//printf("tam = %ld\n",sizeof(char) * strlen(ne));
	if(!(aca->array[u]->represents = calloc(strlen(ne) + 1, sizeof(char)))){
		puts("Não foi possível alocar memória para a string de um nó");
		exit(-1);
	}
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wstringop-truncation"
	strncpy(aca->array[u]->represents, ne, strlen(ne));
	#pragma GCC diagnostic pop
	insert_ix(aca, u, ix);
}

void mostra_estados(struct node_array* aca){
	for(int i = 0; i < aca->array_size; i++){
		for(int j = 0; j < S; j++){
			if(aca->array[i]->nxt[j] != -1){
				printf("%d - %c || %d - %d --> %s\n", i, TO_C(j), aca->array[i]->nxt[j], aca->array[aca->array[i]->nxt[j]]->leaf,
						 aca->array[aca->array[i]->nxt[j]]->represents ? aca->array[aca->array[i]->nxt[j]]->represents : "X");
			}
		}
	}
}


int _link(struct node_array* aca, int u){
	if(aca->array[u]->lnk != -1)
		return aca->array[u]->lnk;
	if( u == 0 || aca->array[u]->p == 0)
		return aca->array[u]->lnk = 0;
	return aca->array[u]->lnk = go(aca, _link(aca, aca->array[u]->p), aca->array[u]->pc);
}

int go(struct node_array* aca, int u, int c){
	if(aca->array[u]->go[c] != -1)
		return aca->array[u]->go[c];

	if(aca->array[u]->nxt[c] != -1)
		return aca->array[u]->go[c] = aca->array[u]->nxt[c];

	if (u == 0)
		return aca->array[u]->go[c] = 0;

	return aca->array[u]->go[c] = go(aca, _link(aca, u), c);
}

//int occ[N];

//struct vetor_e_tamanho occix[N];

// Retorna true se houve uma coincidência
bool process(struct node_array* aca, char* hay){
	int u = 0;
	for(int i = 0; i < strlen(hay); i++){
		int ch = TO_I(hay[i]);
		u = go(aca, u, ch);
		for(int v = u; v != 0; v = out(aca, v)){
			/*
			struct node* n = aca->array[v];
			for(int k = 0; k < n->ix_size; k++){
				int j = n->ix[k];
				//occix[j].array[occix[j].size++] = i - aca->array[v]->depth;
				//printf("occix[%d].array[%d] = %d\n", j, occix[j].size, i - aca->array[v]->depth);
			}
			*/
			//printf("aaaa\n");
			aca->array[v]->occ++;
		}
	}
	for(int u = 0; u < aca->array_size; u++){
		struct node* n = aca->array[u];
		for(int k = 0; k < n->ix_size; k++){
			//int j = n->ix[k];
			//printf("%d\n", aca->array[u]->occ);
			if(n->occ == 0)
				return false;
			
			//occ[j] += aca->array[u]->occ;
		}
	}
	return true;
}

int out(struct node_array* aca, int u){
	if(aca->array[u]->out != -1)
		return aca->array[u]->out;

	int v = _link(aca, u);
	if(v == 0 || aca->array[v]->leaf)
		return aca->array[u]->out = v;

	return aca->array[u]->out = out(aca, v);
}

struct node_array* init_node_array(){
	struct node_array* aca = malloc(sizeof(struct node_array));
	if(!(aca->array = malloc(sizeof(struct node*) * AC_AUTOMATON_SIZE))){
		puts("Não foi possível alocar memória para o autômato");
		exit(-1);
	}
	aca->array[0] = init_node();
	aca->array_size = 1;

	return aca;
}

struct node_array* get_ac_automaton(char** fps, size_t p_len){
	struct node_array* aca = init_node_array();
	for(int i = 0; i < p_len; i++){
		ins(aca, fps[i], i);
	}
	return aca;
}

void free_automaton(struct node_array* aca){
	for(int i = 0; i < aca->array_size; i++){
		free(aca->array[i]->represents);
		free(aca->array[i]->ix);
		free(aca->array[i]);
	}
	free(aca->array);
	free(aca);
}

 //int main(){
 //	struct node_array* aca = init_node_array();
 //
 //	/* Inicialização do Vetor de Ocorrências */
 // //	for(int i = 0; i < N; i++){
 // //		occ[i] = 0;
 // //		occix[i].array = calloc(200, sizeof(int));
 // //		occix[i].size = 0;
 // //	}
 //
 //	char t[50];
 //	strcpy(t, "amids");
 //	ins(aca, t, 0);
 //	strcpy(t, "zads");
 //	ins(aca, t, 1);
 //	strcpy(t, "deds");
 //	ins(aca, t, 2);
 //	
 //	strcpy(t, "inha");
 //	ins(aca, t, 3);
 //
 //
 //	char s[1024];
 //	strcpy(s, "galinhacaipira");
 //
 //	process(aca, s);
 //
 //	/*for(int i = 0; i < 3; i++){
 //		printf("occ[%d] = %d\n", i, occ[i]);
 //		//printf("occix[%d]:\n", i);
 //		for(int j = 0; j < occix[i].size; j++)
 //			printf("occix[%d].array[%d] = %d\n", i, j, occix[i].array[j]);
 //		printf("---\n");
 //	}
 //	*/
 //
 //	//mostra_estados(aca);
 //
 //	/* Liberação das Estruturas */
 //	for(int i = 0; i < aca->array_size; i++){
 //		free(aca->array[i]->represents);
 //		free(aca->array[i]->ix);
 //		free(aca->array[i]);
 //	}
 //	free(aca->array);
 //	free(aca);
 //	
 //	return 0;
 //}

