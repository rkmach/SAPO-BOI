#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include "ppk_parser.h"

//static void ppk_handle_port_neg (struct ahocora_trie *trie, int *src_port, int *idx, int port_idx, int **array, int* array_idx) ;


static inline void PPK_ERR(int err, const char* func_name){
        printf("ERROR: %s: %s\n", strerror(err), func_name);
        exit(-err);
}

static int read_line (int fd, uint8_t * buf, int buf_size) {
        int cur_pos = 0;
        ssize_t read_bytes = 0;
        while ((read_bytes = read (fd, buf + cur_pos, 1) > 0)){
                if (buf[cur_pos] == '\n'){
                        break;
                }
                cur_pos++;

                if (cur_pos == buf_size)
                        PPK_ERR (EIO,__func__);
        }

        if(!read_bytes)
                return 0;

        return cur_pos + 1;
}

static int* ppk_parse_ports(uint8_t* buf, int* size){
        uint8_t port[PPK_STR_INT_SIZE] = {0};
        int index = 0, p_index = 0;
        int * ret = malloc(sizeof(int) * PPK_LINE_SIZE);
        if (!ret)
                PPK_ERR (ENOMEM,__func__);

        for(int i = 0; i < *size; i++){
                if(buf[i] == ' ' || buf[i] == '\n'){
                        ret[index++] = atoi(port);   
                        memset(port, 0, PPK_STR_INT_SIZE);
                        p_index = 0;
                        continue;
                }
                port[p_index++] = buf[i];
        }
        *size = index;
        ret = realloc(ret, sizeof(int) * index);
        if (!ret)
                PPK_ERR (ENOMEM,__func__);

        return ret;
}

static struct ppk_port_pair* ppk_read_ports(int fd){
        struct ppk_port_pair* port_pair = malloc(sizeof(struct ppk_port_pair));
        if (!port_pair)
                PPK_ERR (ENOMEM,__func__);

        uint8_t* buf = malloc(PPK_LINE_SIZE);
        if (!buf)
                PPK_ERR (ENOMEM,__func__);

        memset (buf, 0x7, PPK_LINE_SIZE);
        int size = read_line(fd, buf, PPK_LINE_SIZE);
        if(!size){
                free(port_pair);
                free (buf);
                return 0;
        }
        port_pair->src_port = ppk_parse_ports(buf, &size);
        //printf("src = %d\n", port_pair->src_port[0]);


        port_pair->size_src_port = size;
        size = read_line(fd, buf, PPK_LINE_SIZE);

        port_pair->dst_port = ppk_parse_ports(buf, &size);
        port_pair->size_dst_port = size;

        free(buf);
        return port_pair;
}


static int ppk_read_int(int fd, int* field){
        uint8_t buf[PPK_STR_INT_SIZE];
        int size = read_line(fd, buf, PPK_STR_INT_SIZE);
        if(size <= 0)
                return 0;
        buf[size - 1] = 0;
        *field = atoi(buf);
        return 1;
}


static void ppk_parse_bitmap(struct ppk_content* content, int bitmap,
                uint8_t * options)
{
        if (bitmap & PPK_FAST_PAT)
                content->fast_pat = 1;
        if (bitmap & PPK_NOCASE)
                content->nocase = 1;

        if ( !(bitmap & (PPK_DEPTH | PPK_OFFSET | PPK_DISTANCE | PPK_WITHIN)))
                return;

        uint8_t cur_option [PPK_STR_INT_SIZE] = {0};

        int idx = 0;
        int cur_option_int = 0;
        for(int i = 0; i < strlen (options) + 1; i++){
                if(options[i] == ' ' || options[i] == 0){
                        cur_option_int = atoi(cur_option);   
                        memset(cur_option, 0, PPK_STR_INT_SIZE);
                        idx = 0;
                        if (bitmap & PPK_DEPTH){
                                content->depth = cur_option_int;
                                bitmap &= ~(PPK_DEPTH & 0b1111);
                        }
                        else if (bitmap & PPK_OFFSET){
                                content->offset = cur_option_int;
                                bitmap &= ~(PPK_OFFSET & 0b1111);
                        }

                        else if (bitmap & PPK_DISTANCE){
                                content->distance = cur_option_int;
                                bitmap &= ~(PPK_DISTANCE & 0b1111);
                        }

                        else if (bitmap & PPK_WITHIN){
                                content->within = cur_option_int;
                                bitmap &= ~(PPK_WITHIN & 0b1111);
                        }
                        continue;
                }
                cur_option[idx++] = options[i];
        }
}

static int ppk_read_contents(int fd, struct ppk_content* content){
        content->pattern = malloc(sizeof(uint8_t) * content->size_pattern); 
        if (!content->pattern){
                PPK_ERR(ENOMEM,__func__);
        }

        content->pos = lseek (fd, 0, SEEK_CUR);
        int ret = read(fd, content->pattern, content->size_pattern);
        if(ret != content->size_pattern){
                puts("fdsdsdsfdsfsdfsdfdsfdsdffdsfsd");
                PPK_ERR (EIO,__func__);
        }
        lseek (fd, content->pos + content->size_pattern + 1, SEEK_SET);

        return 0;
}


static void  ppk_read_nrules(int fd, struct ppk_port_pair* port_pair) {
        ppk_read_int(fd, &port_pair->num_rules);

        port_pair->rules = malloc(sizeof(struct ppk_rule *) *
                        port_pair->num_rules);

        if (!port_pair->rules)
                PPK_ERR(ENOMEM,__func__);
}

static void ppk_read_options(int fd, struct ppk_content* content){
        int bitmap = 0;
        ppk_read_int(fd, &bitmap);
        uint8_t buf [PPK_LINE_SIZE] = {0};
        read_line(fd, buf, PPK_LINE_SIZE);

        ppk_parse_bitmap(content, bitmap, buf);

}
static void ppk_read_ncontents (int fd, struct ppk_rule *rule,
                int *num_contents)
{
        ppk_read_int(fd, num_contents);
        rule->contents = malloc (
                        sizeof(struct ppk_content) * rule->num_contents);
        if (!rule->contents)
                PPK_ERR (ENOMEM, __func__);
        memset (rule->contents, 0, sizeof (struct ppk_content));
}

static struct ppk_port_pair** ppk_read_nports (int fd, int *port_pairs_size)
{
        struct ppk_port_pair **port_pairs;
        int num_ports;
        ppk_read_int (fd, &num_ports);

        port_pairs = (struct ppk_port_pair**) malloc (
                        sizeof (struct ppk_port_pair*) * num_ports);
        *port_pairs_size = num_ports;
        if (!port_pairs)
                PPK_ERR (ENOMEM, __func__);
        return port_pairs;
}

void ppk_automaton_fill_rules_array(int fd, struct ppk_rule** rules){
        int curr_state = PPK_STATE_RRULEINDEX;
        int curr_index;
        struct ppk_rule* curr_rule;
        struct ppk_content *curr_content;
        int content_index = 0;
        int ret;
        while(1){
                switch(curr_state){
                        case PPK_STATE_RRULEINDEX:
                                ret = ppk_read_int(fd, &curr_index);
                                if(!ret){
                                        return;
                                }
                                curr_rule = malloc(sizeof(struct ppk_rule));
                                curr_state = PPK_STATE_RSID;
                                break;
                        case PPK_STATE_RSID:
                                //printf("%s\n","PPK_STATE_RSID");
                                ppk_read_int(fd, &curr_rule->sid);
                                //printf("sid = %d\n", curr_rule->sid);
                                curr_state = PPK_STATE_RNCONTENTS;
                                break;
                        case PPK_STATE_RNCONTENTS:
                                //printf("%s\n","PPK_STATE_RNCONTENTS");
                                content_index = 0;
                                ppk_read_ncontents (fd, curr_rule,
                                                &curr_rule->num_contents);
                                curr_content =
                                        &curr_rule->contents[content_index];
                                curr_state = PPK_STATE_RNBYTES;
                                break;
                        case PPK_STATE_RNBYTES:
                                //printf("%s\n","PPK_STATE_RNBYTES");
                                ppk_read_int(fd, &curr_content->size_pattern);
                                curr_state = PPK_STATE_RCONTENT;
                                break;
                        case PPK_STATE_RCONTENT:
                                //printf("%s\n","PPK_STATE_RCONTENT");
                                ppk_read_contents(fd, curr_content);
                                curr_state = PPK_STATE_ROPTIONS;
                                break;
                        case PPK_STATE_ROPTIONS:
                                //printf("%s\n","PPK_STATE_ROPTIONS");
                                ppk_read_options(fd, curr_content);
                                content_index++;
                                if(content_index == curr_rule->num_contents){
                                        curr_state = PPK_STATE_RRULEINDEX;
                                        rules[curr_index] = curr_rule;
                                }
                                // nao eh ultimo content
                                else{
                                        curr_content = &curr_rule->contents[content_index];
                                        curr_state = PPK_STATE_RNBYTES;
                                }
                                break;
                }
        }
}

struct ppk_port_pair** ppk_automaton(int fd, int *port_pairs_size, struct ppk_rule** rules){
        int curr_state = PPK_STATE_RNPORTS;

        struct ppk_port_pair **port_pairs = 0;
        struct ppk_port_pair* curr_port_pair = 0;
        int port_pair_index = 0;
        int cont = 0;
        while(1){
                switch (curr_state){
                        case PPK_STATE_RNPORTS:
                                port_pairs = ppk_read_nports (fd,
                                                port_pairs_size);
                                curr_state = PPK_STATE_RPORTS;
                                break;
                        case PPK_STATE_RPORTS:
                                //printf("%s\n","PPK_STATE_RPORTS");
                                curr_port_pair = ppk_read_ports(fd);
                                if(!curr_port_pair)  {
                                        //printf("NUM REGRAS = %d\n", cont);
                                        return port_pairs; 
                                }
                                curr_state = PPK_STATE_RNRULES;
                                break;
                        case PPK_STATE_RNRULES:
                                //printf("%s\n","PPK_STATE_RNRULES");
                                ppk_read_nrules(fd, curr_port_pair);  // aloquei vetor de ponteiro de regras
                                curr_state = PPK_STATE_RRULEINDEX;
                                break;
                        case PPK_STATE_RRULEINDEX:
                                cont++;
                                //printf("%s\n","PPK_STATE_RSID");
                                int idx;
                                for(int i = 0; i < curr_port_pair->num_rules; i++){
                                        ppk_read_int(fd, &idx);
                                        curr_port_pair->rules[i] = rules[idx];  // li a posição q ta a regra
                                }
                                port_pairs[port_pair_index++] = curr_port_pair;
                                curr_state = PPK_STATE_RPORTS;
                                break;
                }
        }
}

/*
static void ppk_add_single_port (struct ahocora_trie *trie, int port,
                int port_idx, int ** array, int* array_idx)
{
        array[port][array_idx[port]++] = port_idx;
}

static void ppk_handle_port_range (struct ahocora_trie *trie, int *src_port,
                int *idx, int neg, int any, int port_idx, int ** array,
                int* array_idx)
{
        int first;
        int last;

        if (any){
                first = 0;
                last = PPK_LAST_PORT;
        }
        else{
                first = src_port[(*idx)++];
                last = src_port[(*idx)++];
        }

        if (!neg) {
                for (int i = first ; i <= last ; i++){
                        ppk_add_single_port (trie, i, port_idx, array,
                                        array_idx);
                }
        }
        else {
                for (int i = 0 ; i < first ; i++)
                        ppk_add_single_port (trie, i, port_idx, array,
                                        array_idx);
                for (int i = last + i ; i <= PPK_LAST_PORT ; i++)
                        ppk_add_single_port (trie, i, port_idx, array,
                                        array_idx);
        }
}


static void ppk_handle_port_array (struct ahocora_trie *trie, int *src_port, int *idx, int neg, int port_idx, int ** array, int* array_idx)
{
        int size = src_port[(*idx)++];
        int cur_port;

        if (!neg){
                for (int i = 0 ; i < size ; i++){
                        cur_port = src_port[(*idx)++];
                        if (cur_port > 0)
                                ppk_add_single_port (trie, *idx, port_idx,
                                                array, array_idx);
                        else if (cur_port == PPK_RANGE)
                                ppk_handle_port_range (trie, src_port, idx, 0,
                                                0, port_idx, array, array_idx);
                        else if (cur_port == PPK_NEG)
                                ppk_handle_port_neg (trie, src_port, idx,
                                                port_idx, array, array_idx);
                }

                return;
        }

        int count = 0;
        for (int i = 0 ; i <= PPK_LAST_PORT ; i++){
                if (count == size){
                        for (; i <= PPK_LAST_PORT ; i++)
                                ppk_add_single_port (trie, i, port_idx, array, array_idx);

                        break;
                }
                count ++;

                cur_port = src_port[(*idx)++];
                if (cur_port > 0){
                        if (i < cur_port){
                                for (; i < cur_port ; i++)
                                        ppk_add_single_port (trie, i, port_idx, array, array_idx);
                        }
                        continue;
                }
                else if (cur_port == PPK_RANGE){
                        cur_port = src_port[(*idx)++];
                        if (i < cur_port){
                                for (; i < cur_port ; i++)
                                        ppk_add_single_port (trie, i, port_idx, array, array_idx);
                        }
                        i =  src_port[(*idx)++];
                }
                else 
                        PPK_ERR (EINVAL, __func__);
        }
}

static void ppk_handle_port_neg (struct ahocora_trie *trie, int *src_port,
                int *idx, int port_idx, int ** array, int* array_idx) 
{
        int cur_port = src_port[(*idx)++];

        if (cur_port > 0){
                for (int i = 0 ; i <= PPK_LAST_PORT ; i++)
                        if (i != cur_port)
                                ppk_add_single_port (trie, i, port_idx, array,
                                                array_idx);
        }

        else if (cur_port == PPK_RANGE)
                ppk_handle_port_range (trie, src_port, idx, 1, 0, port_idx,
                                array, array_idx);

        else if (cur_port == PPK_ARRAY)
                ppk_handle_port_array (trie, src_port, idx, 1, port_idx, array,
                                array_idx);
}

void __ppk_register_fp_trie (struct ppk_port_pair *port_pair, int port_idx,
                int* cur_port_array, int port_array_size, int** array,
                int* array_idx)
{
        for (int i = 0 ; i < port_array_size; i++)
        {
                if (cur_port_array[i] > 0)
                        ppk_add_single_port (port_pair->fp_trie,
                                cur_port_array[i], port_idx, array, array_idx);
                else if (cur_port_array[i] == PPK_RANGE){
                        i++;
                        ppk_handle_port_range (port_pair->fp_trie,
                                        cur_port_array, &i, 0, 0, port_idx,
                                        array, array_idx);
                        --i;
                }
                else if (cur_port_array[i] == 0){
                        i++;
                        ppk_handle_port_range (port_pair->fp_trie,
                                        cur_port_array, &i, 0, 1, port_idx,
                                        array, array_idx);
                        --i;
                }
                else if (cur_port_array[i] == PPK_NEG){
                        i++;
                        ppk_handle_port_neg (port_pair->fp_trie, cur_port_array,
                                        &i, port_idx, array, array_idx);
                        --i;
                }
                else if (cur_port_array[i] == PPK_ARRAY){
                        i++;
                        ppk_handle_port_array (port_pair->fp_trie,
                                        cur_port_array, &i, 0, port_idx, array,
                                        array_idx);
                        --i;
                }
                else{
                        PPK_ERR (EINVAL, __func__);
                }

        }

}



static void ppk_register_fp_trie (struct ppk_port_pair *port_pair, int port_idx,
               int** src_array, int* src_array_idx, int** dst_array,
               int* dst_array_idx)
{
        __ppk_register_fp_trie(port_pair, port_idx, port_pair->src_port,
                        port_pair->size_src_port, src_array, src_array_idx);
        __ppk_register_fp_trie(port_pair, port_idx, port_pair->dst_port,
                        port_pair->size_dst_port, dst_array, dst_array_idx);
}
*/

void ppk_create_ahocora_fp_automata (struct ppk_port_pair **port_pairs,
                int size)
{
        struct ppk_port_pair *cur_port_pair;
        struct ppk_rule *cur_rule;
        struct ppk_content *cur_content;
        for (int i = 0 ; i < size ; i++)
        {
                cur_port_pair = port_pairs[i];
                cur_port_pair->fp_trie = ahocora_create_trie ();
                for (int j = 0 ; j < cur_port_pair->num_rules ; j++)
                {
                        cur_rule = cur_port_pair->rules[j];
                        
                        for (int k = 0 ; k < cur_rule->num_contents ; k++)
                        {
                                cur_content = cur_rule->contents + k;
                                if (cur_content->fast_pat){
                                        ahocora_insert_pattern(
                                                cur_port_pair->fp_trie,
                                                cur_content->pattern,
                                                cur_content->size_pattern,
                                                cur_rule->sid
                                        );
                                }
                                //free (cur_content->pattern);
                        }


                }
                ahocora_build_suffix_links (cur_port_pair->fp_trie);
                ahocora_build_dict_suffix_links (cur_port_pair->fp_trie);

                //ppk_register_fp_trie (cur_port_pair, i, src_array,
                //                src_array_idx, dst_array, dst_array_idx);
                //printf("i = %d --- trie size = %d\n", i, cur_port_pair->fp_trie->size);
                cur_port_pair->fp_trie->array = realloc(cur_port_pair->fp_trie->array, sizeof(struct ahocora_node*) * cur_port_pair->fp_trie->size);
        }
}


void ppk_create_ahocora_automata (struct ppk_port_pair **port_pairs, int size)
{
        struct ppk_port_pair *cur_port_pair;
        struct ppk_rule *cur_rule;
        struct ppk_content *cur_content;
        for (int i = 0 ; i < size ; i++){
                //printf("i = %d\n", i);
                cur_port_pair = port_pairs[i];
                for (int j = 0 ; j < cur_port_pair->num_rules ; j++){
                        cur_rule = cur_port_pair->rules[j];
                        cur_rule->trie = ahocora_create_trie();
                        for (int k = 0 ; k < cur_rule->num_contents ; k++) {
                                cur_content = cur_rule->contents + k;
                                ahocora_insert_pattern (cur_rule->trie,
                                                cur_content->pattern,
                                                cur_content->size_pattern,
                                                cur_rule->sid);
                        }
                        ahocora_build_suffix_links (cur_rule->trie);
                        ahocora_build_dict_suffix_links (cur_rule->trie);

                }
        }
}

void ppk_read_rule_array_size(int fd, int* size){
        ppk_read_int(fd, size);
}

/*
int main(){
        int rules_tcp_fd = open("rules_tcp.perereca", O_RDONLY);
        if(rules_tcp_fd < 0)
                exit(-1);
        int tcp_len_array_rules, udp_len_array_rules;
        ppk_read_rule_array_size(rules_tcp_fd, &tcp_len_array_rules);
        printf("tcp_len_array_rules = %d\n", tcp_len_array_rules);
        struct ppk_rule** tcp_rules_array = malloc(sizeof(struct ppk_rule*) * tcp_len_array_rules);
        ppk_automaton_fill_rules_array(rules_tcp_fd, tcp_rules_array);
        close(rules_tcp_fd);


        int tcp_fd = open("sapo_boi_tcp_rules.perereca", O_RDONLY);
        if (tcp_fd < 0)
                exit(-1);
        int tcp_port_pair_size = 0;
        struct ppk_port_pair **tcp_port_pairs = ppk_automaton (tcp_fd, &tcp_port_pair_size, tcp_rules_array);
        //printf("tcp size = %d\n", tcp_port_pair_size);
        close (tcp_fd);
        for(int i = 0; i < tcp_port_pair_size; i++){
                printf("src = %d -- dst = %d\n", tcp_port_pairs[i]->src_port[0], tcp_port_pairs[i]->dst_port[0]);
                for (int j = 0; j < tcp_port_pairs[i]->num_rules; j++){
                        printf("sid = %d\n", tcp_port_pairs[i]->rules[j]->sid);
                }
                puts("");
        }

        for(int i = 0; i < tcp_len_array_rules; i++){
                free(tcp_rules_array[i]->contents);
                free(tcp_rules_array[i]);
        }
        free(tcp_rules_array);

        getchar();


        int rules_udp_fd = open("rules_udp.perereca", O_RDONLY);
        ppk_read_rule_array_size(rules_udp_fd, &udp_len_array_rules);
        printf("udp_len_array_rules = %d\n", udp_len_array_rules);
        struct ppk_rule** udp_rules_array = malloc(sizeof(struct ppk_rule*) * udp_len_array_rules);
        ppk_automaton_fill_rules_array(rules_udp_fd, udp_rules_array);
        close(rules_udp_fd);

        int udp_fd = open("sapo_boi_udp_rules.perereca", O_RDONLY);
        if (udp_fd < 0)
                exit(-1);
        int udp_port_pair_size = 0;
        struct ppk_port_pair **udp_port_pairs = ppk_automaton (udp_fd, &udp_port_pair_size, udp_rules_array);
        //printf("udp size = %d\n", udp_port_pair_size);
        close (udp_fd);
        for(int i = 0; i < udp_port_pair_size; i++){
                printf("src = %d -- dst = %d\n", udp_port_pairs[i]->src_port[0], udp_port_pairs[i]->dst_port[0]);
                for (int j = 0; j < udp_port_pairs[i]->num_rules; j++){
                        printf("sid = %d\n", udp_port_pairs[i]->rules[j]->sid);
                }
                puts("");
        }

        
        ppk_create_ahocora_automata (udp_port_pairs, udp_port_pair_size);
        ppk_create_ahocora_automata (tcp_port_pairs, tcp_port_pair_size);

        ppk_create_ahocora_fp_automata(udp_port_pairs, udp_port_pair_size);
        ppk_create_ahocora_fp_automata(tcp_port_pairs, tcp_port_pair_size);
        //char input [30] = {'\x00','\x01','\x00','\x00','\x00','\x00','\x00','\x00','i','s','\x03','b', 'i', 'z', '\x00','\x00','\x01','\x00','\x01'};

        puts("aaaaaaaaaaaaaaa");
        return 0;
}
        */

