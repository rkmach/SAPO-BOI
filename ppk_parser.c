#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include "ppk_parser.h"

static inline void PPK_ERR(int err, const char* func_name){
        printf("ERROR: %s: %s\n", strerror(err), func_name);
        exit(-err);
}

static int read_line (int fd, char * buf, int buf_size) {
        int cur_pos = 0;
        ssize_t read_bytes = 0;
        while (read_bytes = read (fd, buf + cur_pos, 1) > 0){
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

static int* ppk_parse_ports(char* buf, int* size){
        char port[PPK_STR_INT_SIZE] = {0};
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
        ret = realloc(ret, index);
        if (!ret)
                PPK_ERR (ENOMEM,__func__);

        return ret;
}

static struct ppk_port_pair* ppk_read_ports(int fd){
        struct ppk_port_pair* port_pair = malloc(sizeof(struct ppk_port_pair));
        if (!port_pair)
                PPK_ERR (ENOMEM,__func__);

        char* buf = malloc(PPK_LINE_SIZE);
        if (!buf)
                PPK_ERR (ENOMEM,__func__);

        int size = read_line(fd, buf, PPK_LINE_SIZE);
        if(!size){
                free(port_pair);
                free (buf);
                return 0;
        }
        port_pair->src_port = ppk_parse_ports(buf, &size);


        port_pair->size_src_port = size;
        size = read_line(fd, buf, PPK_LINE_SIZE);

        port_pair->dst_port = ppk_parse_ports(buf, &size);
        port_pair->size_dst_port = size;

        free(buf);
        return port_pair;
}


static void ppk_read_int(int fd, int* field){
        char buf[PPK_STR_INT_SIZE];
        int size = read_line(fd, buf, PPK_STR_INT_SIZE);
        buf[size - 1] = 0;
        *field = atoi(buf);
}


static void ppk_parse_bitmap(struct ppk_content* content, int bitmap, char * options){
        int options_value [4] = {0};

        if (bitmap & PPK_FAST_PAT)
                content->fast_pat = 1;
        if (bitmap & PPK_NOCASE)
                content->nocase = 1;

        if ( !(bitmap & (PPK_DEPTH | PPK_OFFSET | PPK_DISTANCE | PPK_WITHIN)))
                return;

        char cur_option [PPK_STR_INT_SIZE] = {0};

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
        printf ("content->fast_pat: %d\n", content->fast_pat);
        printf ("content->nocase: %d\n", content->nocase);
        printf ("content->depth: %d\n", content->depth);
        printf ("content->offset: %d\n", content->offset);
        printf ("content->distance: %d\n", content->distance);
        printf ("content->within: %d\n", content->within);
}

static int ppk_read_contents(int fd, struct ppk_content* content){
        content->pattern = malloc(sizeof(char) * content->size_pattern); 
        if (!content->pattern)
                PPK_ERR(ENOMEM,__func__);

        content->pos = lseek (fd, 0, SEEK_CUR);
        int ret = read(fd, content->pattern, content->size_pattern);
        if(ret != content->size_pattern){
                PPK_ERR (EIO,__func__);
        }
        lseek (fd, content->pos + content->size_pattern + 1, SEEK_SET);
        
        return 0;
}


static void  ppk_read_nrules(int fd, struct ppk_port_pair* port_pair) {
        ppk_read_int(fd, &port_pair->num_rules);

        port_pair->rules = malloc(sizeof(struct ppk_rule) *
                        port_pair->num_rules);

        if (!port_pair->rules)
                PPK_ERR(ENOMEM,__func__);
}

static void ppk_read_options(int fd, struct ppk_content* content){
        int bitmap;
        ppk_read_int(fd, &bitmap);
        char buf [PPK_LINE_SIZE] = {0};
        read_line(fd, buf, PPK_LINE_SIZE);

        ppk_parse_bitmap(content, bitmap, buf);
        printf ("HAHHAHAHA\n");

}
static void ppk_read_ncontents (int fd, struct ppk_rule *rule,  int *num_contents)
{
        ppk_read_int(fd, num_contents);
        rule->contents = malloc(sizeof(struct ppk_content) * rule->num_contents);
        if (!rule->contents)
                PPK_ERR (ENOMEM, __func__);
        memset (rule->contents, 0, sizeof (struct ppk_content));
}

int ppk_automaton(int fd){
        int curr_state = PPK_STATE_RPORTS;
        struct ppk_port_pair* curr_port_pair;
        struct ppk_rule* curr_rule;
        struct ppk_content *curr_content;
        int content_index = 0;
        int rule_index = 0;
        int cont = 0;
        while(1){
                switch (curr_state){
                        case PPK_STATE_RPORTS:
                                printf("%s\n","PPK_STATE_RPORTS");
                                printf("cont = %d\n", cont++);
                                curr_port_pair = ppk_read_ports(fd);
                                if(!curr_port_pair)  
                                       return 0; 
                                curr_state = PPK_STATE_RNRULES;
                                break;
                        case PPK_STATE_RNRULES:
                                printf("%s\n","PPK_STATE_RNRULES");
                                rule_index = 0;
                                ppk_read_nrules(fd, curr_port_pair);
                                curr_rule = &curr_port_pair->rules[rule_index];
                                curr_state = PPK_STATE_RSID;
                                break;
                        case PPK_STATE_RSID:
                                printf("%s\n","PPK_STATE_RSID");
                                ppk_read_int(fd, &curr_rule->sid);
                                curr_state = PPK_STATE_RNCONTENTS;
                                break;
                        case PPK_STATE_RNCONTENTS:
                                printf("%s\n","PPK_STATE_RNCONTENTS");
                                content_index = 0;
                                ppk_read_ncontents (fd, curr_rule, &curr_rule->num_contents);
                                curr_content = &curr_rule->contents[content_index];
                                curr_state = PPK_STATE_RNBYTES;
                                break;
                        case PPK_STATE_RNBYTES:
                                printf("%s\n","PPK_STATE_RNBYTES");
                                ppk_read_int(fd, &curr_content->size_pattern);
                                curr_state = PPK_STATE_RCONTENT;
                                break;
                        case PPK_STATE_RCONTENT:
                                printf("%s\n","PPK_STATE_RCONTENT");
                                ppk_read_contents(fd, curr_content);
                                curr_state = PPK_STATE_ROPTIONS;
                                break;
                        case PPK_STATE_ROPTIONS:
                                printf("%s\n","PPK_STATE_ROPTIONS");
                                ppk_read_options(fd, curr_content);
                                content_index++;
                                if(content_index == curr_rule->num_contents){
                                        printf ("AAA\n");
                                        rule_index++;
                                        if(rule_index == curr_port_pair->num_rules){
                                                printf ("BBB\n");
                                                curr_state = PPK_STATE_RPORTS;                
                                        }
                                        else{
                                                printf ("CCC\n");
                                                curr_rule = &curr_port_pair->rules[rule_index];
                                                curr_state = PPK_STATE_RSID;
                                        }
                                }
                                // nao eh ultimo content
                                else{
                                                printf ("DDD\n");
                                        curr_content = &curr_rule->contents[content_index];
                                        curr_state = PPK_STATE_RNBYTES;
                                }
                                break;
                }
        }
}


int main(){
        int fd = open("sapo_boi_udp_rules.perereca", O_RDONLY);
        if (fd < 0) exit(-1);

        ppk_automaton(fd);

        return 0;
}

