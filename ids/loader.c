#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_link.h>
#include <signal.h>
#include <net/if.h>
#include <assert.h>

/* In this example we use libbpf-devel and libxdp-devel */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include "cora.h"

struct xdp_program * prog;

static void int_exit(int sig)
{
        xdp_program__close(prog);
        exit(0);
}

int main ()
{
        prog = xdp_program__open_file ("xdp_drop.o", "FODASE", 0);
        if (!prog)
        {
                printf ("xdp_program__open_file error");
                return 1;
        }

        int ifindex = 8;

        int ret = xdp_program__attach (prog, ifindex, XDP_MODE_SKB, 0);
        if (ret) {
                printf ("xdp_program__attach error");
                return ret;
        }

        struct bpf_object *bpf_obj = xdp_program__bpf_obj (prog);
        int map_fd = bpf_object__find_map_fd_by_name (bpf_obj, "james_map");
        if (map_fd < 0) {
                printf ("bpf_object__find_map_fd_by_name error");
                return map_fd;
        }

        int key = 0;

        struct ahocora_trie * trie = ahocora_create_trie ();
        ahocora_insert_pattern (trie, "abba", 4, 1);
        /*
        ahocora_insert_pattern (trie, "ar", 2, 2);
        ahocora_insert_pattern (trie, "bb", 2, 3);
        ahocora_insert_pattern (trie, "bar", 3, 4);
        ahocora_insert_pattern (trie, "foo", 3, 5);
        ahocora_insert_pattern (trie, "foobar", 6, 6);
        */
        ahocora_print_trie(trie);
        printf("basic_links[97] = %d\n", trie->array[0]->basic_links[97]);


        struct ahocora_node nodes[trie->num_patterns];
        for(int i = 0; i < trie->num_patterns; i++){
                nodes[i].id = trie->array[i]->id;
                for(int j = 0; j < NUM_ACCEPTABLE_SYMBOLS; j++)
                        nodes[i].basic_links[j] = trie->array[i]->basic_links[j];
                nodes[i].suffix_link = trie->array[i]->suffix_link;
                nodes[i].dict_suffix_link = trie->array[i]->dict_suffix_link;
                nodes[i].hit = trie->array[i]->hit;
                nodes[i].rule_sid = trie->array[i]->rule_sid;
                nodes[i].parent = trie->array[i]->parent;
                nodes[i].suffix = trie->array[i]->suffix;
        }
        
        struct ahocora_static_trie static_trie;
        static_trie.array = nodes;
        static_trie.size = trie->size;
        static_trie.num_patterns = trie->num_patterns;


        if(bpf_map_update_elem(map_fd, &key, &static_trie, 0) < 0)
                puts("DEU PAU");

        struct ahocora_static_trie map_value;
        getchar();
        bpf_map_lookup_elem (map_fd, &key, &map_value);

        printf ("DEPOIS num_patterns: %d\n", map_value.num_patterns);
        //printf("num_pattens = %d\n", trie->num_patterns);
        
        return 0;

}
