#include "cora.h"

static struct ahocora_node* ahocora_create_node () 
{
        struct ahocora_node * node = malloc (sizeof (struct ahocora_node));
        memset (node, 0, sizeof (struct ahocora_node));
        node->id = -1;
        node->suffix_link = -1;
        node->dict_suffix_link = -1;
        node->rule_sid = -1;
        node->parent = -1;
        for (int i = 0 ; i < NUM_ACCEPTABLE_SYMBOLS ; i++)
                node->basic_links[i] = -1;

        return node;
}

void ahocora_print_trie (struct ahocora_trie *trie)
{
        struct ahocora_node *cur_node;
        for (int i = 0 ; i < trie->size ; i++){
                cur_node = trie->array[i];
                printf ("----- NODE %d -----\n", i);
                printf ("suffix_link: %d\n", cur_node->suffix_link);
                printf ("dict_suffix_link: %d\n", cur_node->dict_suffix_link);
                printf ("parent: %d\n", cur_node->parent);
                printf ("suffix: %hhx[%c]\n", cur_node->suffix,
                                cur_node->suffix);
                if (cur_node->rule_sid != -1)
                {
                        printf ("hit: %d\n", cur_node->hit);
                        printf ("rule_sid: %d\n", cur_node->rule_sid);
                }

                printf ("basic_links: \n");
                for (int j = 0 ; j < NUM_ACCEPTABLE_SYMBOLS ; j ++){
                        if (cur_node->basic_links[j] != -1)
                                printf ("\tbasic_link[%hhx(%c)]: %d\n", j, j,
                                                cur_node->basic_links[j]);
                }
                printf ("----- NODE %d -----\n\n", i);
        }
}

static int ahocora_lookup (struct ahocora_trie *trie, uint8_t *pattern,
                int size)
{
        struct ahocora_node *cur_node = trie->array[0];
        uint8_t next_byte;
        for (int i = 0 ; i < size ; i++){
                next_byte = pattern[i];
                if (cur_node->basic_links[next_byte] == -1){
                        return -1;
                }
                cur_node = trie->array[cur_node->basic_links[next_byte]];
        }
        return cur_node->id;
}


static int ahocora_find_best_suffix_link (struct ahocora_trie *trie,
                struct ahocora_node *node, uint8_t *longest_pattern,
                int pattern_size, int best_node, int original_node)
{
        if (node->parent == 0){
                return best_node;

        }

        int new_best_node = ahocora_lookup(trie, longest_pattern, pattern_size);

        memmove (longest_pattern + 1, longest_pattern, pattern_size);
        longest_pattern[0] = trie->array[node->parent]->suffix;
        longest_pattern[++pattern_size] = 0;

        if (new_best_node == -1)
                return ahocora_find_best_suffix_link (trie,
                                trie->array[node->parent], longest_pattern,
                                pattern_size, best_node, original_node);
        else 
                return ahocora_find_best_suffix_link (trie,
                                trie->array[node->parent], longest_pattern,
                                pattern_size, new_best_node, original_node);
        

}


static void __ahocora_build_dict_suffix_links (struct ahocora_trie *trie,
                struct ahocora_node *node, uint8_t *longest_pattern, int size)
{
        int target_node;
        uint8_t *original_pattern = longest_pattern;
        int original_size = size;
        for (int i = 0 ; i < original_size - 1 ; i++){
                if (size == 0)
                        break;
                target_node = ahocora_lookup (trie, longest_pattern + 1,
                                size - 1);
                if (target_node == -1){
                        longest_pattern++;
                        size--;
                }
                else if (trie->array[target_node]->rule_sid != -1){
                        node->dict_suffix_link = target_node;
                        break;
                }
        }

        struct ahocora_node *next_node;
        size = original_size;
        longest_pattern = original_pattern;
        for (int i = 0 ; i < NUM_ACCEPTABLE_SYMBOLS ; i++){
                if (node->basic_links[i] == -1)
                        continue;
                next_node = trie->array[node->basic_links[i]];
                longest_pattern[size++] = next_node->suffix;
                longest_pattern[size] = 0;
                __ahocora_build_dict_suffix_links (trie, next_node,
                                longest_pattern, size);
                size = original_size;
        }
}


void ahocora_build_dict_suffix_links (struct ahocora_trie *trie)
{
        uint8_t *longest_pattern = malloc (MAX_FRAME_SIZE);
        memset (longest_pattern, 0 , MAX_FRAME_SIZE);

        for (int i = 0 ; i < trie->size ; i++)
                trie->array[i]->dict_suffix_link = -1;

        __ahocora_build_dict_suffix_links (trie, trie->array[0],
                        longest_pattern, 0);

        free (longest_pattern);

}

void ahocora_insert_pattern (struct ahocora_trie *trie, uint8_t *pattern,
                int pattern_size, int rule_sid)
{
        struct ahocora_node * cur_node = trie->array[0];
        int new_final_state = 0;
        for (int i = 0 ; i < pattern_size ; i++) {
                uint8_t cur_byte = 0;
                cur_byte = pattern[i];

                if(cur_node->basic_links[cur_byte] != -1){
                        cur_node =
                                trie->array[cur_node->basic_links[cur_byte]];
                        continue;
                }
                new_final_state = 1;

                struct ahocora_node *new_node = ahocora_create_node();

                new_node->suffix = cur_byte;
                new_node->parent = cur_node->id;
                new_node->id = trie->size;

                trie->array[trie->size++] = new_node;

                cur_node->basic_links[cur_byte] = new_node->id;
                cur_node = new_node;
        }

        if (new_final_state)
                trie->num_patterns++;

        cur_node->rule_sid = rule_sid;
}


void ahocora_build_suffix_links (struct ahocora_trie *trie)
{
        struct ahocora_node *cur_node;
        uint8_t *longest_pattern = malloc (MAX_FRAME_SIZE);
        memset (longest_pattern, 0 , MAX_FRAME_SIZE);

        for (int i = 0 ; i < trie->size ; i++)
                trie->array[i]->suffix_link = -1;

        for (int i = 1 ; i < trie->size; i++){
                cur_node = trie->array[i];
                longest_pattern[0] = cur_node->suffix;
                cur_node->suffix_link = ahocora_find_best_suffix_link (trie,
                                cur_node, longest_pattern, 1, 0, cur_node->id);
        }
        free (longest_pattern);

}


struct ahocora_trie* ahocora_create_trie ()
{
        struct ahocora_trie * trie = malloc (sizeof (struct ahocora_trie));
        memset (trie, 0, sizeof (struct ahocora_trie));
        trie->array = malloc (sizeof(struct ahocora_node*) * AC_AUTOMATON_SIZE);

        struct ahocora_node * root = ahocora_create_node();
        root->id = 0;

        trie->array[0] = root;
        trie->size = 1;

        return trie;
}

static inline int ahocora_count_dict_hits (struct ahocora_trie *trie,
                struct ahocora_node *node, int hits)
{
        if (node->dict_suffix_link == -1) {
                if (node->hit == 0){
                        node->hit = 1;
                        return hits + 1;
                }
                else
                        return hits;
        }

        struct ahocora_node *next_node = trie->array[node->dict_suffix_link];

        if (node->hit == 0){
                node->hit = 1;
                return ahocora_count_dict_hits (trie, next_node, hits + 1);
        }
        else
                return ahocora_count_dict_hits (trie, next_node, hits);
}

int ahocora_search (struct ahocora_trie *trie, uint8_t *input, int size)
{
        int num_found_patterns = 0;
        struct ahocora_node *node = trie->array[0];
        for (int i = 0 ; i < size + 1 ; i++){
                printf ("looking %hhx[%c]\n", input[i],  input[i]);
                if (node->rule_sid != -1 && node->hit == 0){
                        node->hit = 1;
                        num_found_patterns++;
                }
                if (node->dict_suffix_link != -1) {
                        num_found_patterns += ahocora_count_dict_hits (trie,
                                        trie->array[node->dict_suffix_link], 0);
                }

                if (trie->num_patterns == num_found_patterns)
                        return num_found_patterns;

                if (i < size) {
                        if (node->basic_links[input[i]] == -1){
                                if (node->id == 0)
                                        continue;
                                node = trie->array[node->suffix_link];
                                i--;
                        }
                        else 
                                node = trie->array[node->basic_links[input[i]]];

                }
        }
        return num_found_patterns;
}
 
/*
int main ()
{
        struct ahocora_trie * trie = ahocora_create_trie ();
        
        ahocora_insert_pattern (trie, "abba", 4, 1);
        ahocora_insert_pattern (trie, "ar", 2, 2);
        ahocora_insert_pattern (trie, "bb", 2, 3);
        ahocora_insert_pattern (trie, "bar", 3, 4);
        ahocora_insert_pattern (trie, "foo", 3, 5);
        ahocora_insert_pattern (trie, "foobar", 6, 6);
        
        ahocora_insert_pattern (trie, "a", 1, 1);
        ahocora_insert_pattern (trie, "ab", 2, 2);
        ahocora_insert_pattern (trie, "bc", 2, 3);
        ahocora_insert_pattern (trie, "bca", 3, 4);
        ahocora_insert_pattern (trie, "c", 1, 5);
        ahocora_insert_pattern (trie, "caa", 3, 6);

        ahocora_insert_pattern (trie, "a",1, 1);
        ahocora_insert_pattern (trie, "ab",2, 2);
        ahocora_insert_pattern (trie, "bab",3, 3);
        ahocora_insert_pattern (trie, "bc",2, 4);
        ahocora_insert_pattern (trie, "bca",3, 5);
        ahocora_insert_pattern (trie, "c",1, 6);
        ahocora_insert_pattern (trie, "caa",3, 7);

        
        ahocora_build_suffix_links (trie);
        ahocora_build_dict_suffix_links (trie);
        ahocora_print_trie (trie);
        printf ("ahocora_search(): %d\n", ahocora_search (trie, "fooarazacaralhabba", 19));
        return 0;
}
*/
