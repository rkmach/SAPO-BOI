#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include "ppk_parser.h"

static int read_line (int fd, char * buf, int buf_size) {
        if (!buf_size)
                return 0;

        int cur_pos = 0;
        while (read (fd, buf + cur_pos, 1) > 0){
                if (buf[cur_pos] == '\n')
                        break;
                cur_pos++;

                if (cur_pos == buf_size)
                        return -1;
        }

        return cur_pos + 1;
}

static int * ppk_parse_ports(char* buf, int* size){
        char port[5] = {0};
        int index = 0, p_index = 0;
        int * ret = malloc(sizeof(int) * PPK_LINE_SIZE);
        for(int i = 0; i < *size; i++){
                if(buf[i] == ' ' || buf[i] == '\n'){
                        ret[index++] = atoi(port);   
                        memset(port, 0, 5);
                        p_index = 0;
                        continue;
                }
                port[p_index++] = buf[i];
        }
        *size = index;
        ret = realloc(ret, index);
        return ret;
}

static struct ppk_port_pair* ppk_read_ports(int fd){
        struct ppk_port_pair* port_pair = malloc(sizeof(struct ppk_port_pair));
        char* buf = malloc(PPK_LINE_SIZE);
        int size = read_line(fd, buf, PPK_LINE_SIZE);
        if(size < 0){
                goto out_error;
        }
        port_pair->src_port = ppk_parse_ports(buf, &size);
        port_pair->size_src_port = size;
        size = read_line(fd, buf, PPK_LINE_SIZE);
        if(size < 0){
                goto out_error;
        }
        port_pair->dst_port = ppk_parse_ports(buf, &size);
        port_pair->size_dst_port = size;

        free(buf);
        return port_pair;


out_error:
        free(port_pair);
        free(buf);
        return 0;
}

static void ppk_read_nrules(int fd, struct ppk_port_pair* port_pair){
        char buf[10];
        int size = read_line(fd, buf, PPK_LINE_SIZE);
        buf[size - 1] = 0;
        if(size < 0)
                return;
        port_pair->num_rules = atoi(buf);
}

static void ppk_read_sid(int fd, struct ppk_rule* rule){
        char buf[10];
        int size = read_line(fd, buf, PPK_LINE_SIZE);
        buf[size - 1] = 0;
        if(size < 0)
                return;
        rule->sid = atoi(buf);
}

static void ppk_read_num_contents(int fd, struct ppk_rule* rule){
        char buf[10];
        int size = read_line(fd, buf, PPK_LINE_SIZE);
        buf[size - 1] = 0;
        if(size < 0)
                return;
        rule->num_contents = atoi(buf);
}

static void ppk_parse_bitmap(struct ppk_rule* rule, int bitmap){
        printf("bitmap = %d\n", bitmap);
        if (bitmap & FAST_PAT){
                printf("FP!!\n");
                bitmap >> FAST_PAT;
        }

        if (bitmap & NOCASE){
                printf("nocase!!\n");
                bitmap >> NOCASE;
        }

        if (bitmap & DEPTH){
                printf("depth!!\n");
                bitmap >> DEPTH;
        }

        if (bitmap & OFFSET){
                printf("offset!!\n");
                bitmap >> OFFSET;
        }

        if (bitmap & DISTANCE){
                printf("distance!!\n");
                bitmap >> DISTANCE;
        }

        if (bitmap & WITHIN){
                printf("within!!\n");
                bitmap >> WITHIN;
        }
}

static void ppk_read_bitmap(int fd, struct ppk_rule* rule){
        char buf[10];
        int buf_size = read_line(fd, buf, PPK_LINE_SIZE);
        buf[buf_size - 1] = 0;
        if(buf_size < 0)
                return;
        printf("AAAAAAAAAAAAAAAAAA\n");
        ppk_parse_bitmap(rule, atoi(buf));
}

static void ppk_read_contents(int fd, struct ppk_rule* rule){
        char buf[10];
        int buf_size = read_line(fd, buf, PPK_LINE_SIZE);
        buf[buf_size - 1] = 0;
        if(buf_size < 0)
                return;
        
        rule->contents = malloc(sizeof(struct ppk_contents*)*rule->num_contents);

        int index_content = 0;
        for(; index_content < rule->num_contents; index_content++){

                rule->contents[index_content] = malloc(
                                sizeof(struct ppk_content));
                printf("AAAAAAAAAAAAAAAAAA\n");
                rule->contents[index_content]->size_pattern = atoi(buf);

                rule->contents[index_content]->pattern = malloc(atoi(buf));
                buf_size = read_line(fd, rule->contents[index_content]->pattern,
                               rule->contents[index_content]->size_pattern);

                ppk_read_bitmap(fd, rule);
        }
}

static void ppk_read_rule(int fd, struct ppk_rule* rule){
        rule = malloc(sizeof(struct ppk_rule));
        int curr_state = PPK_STATE_RSID;
        while(1){
                switch(curr_state){
                        case PPK_STATE_RSID:
                                ppk_read_sid(fd, rule);
                                printf("sid = %d\n", rule->sid);
                                curr_state = PPK_STATE_RNCONTENTS;
                                break;
                        case PPK_STATE_RNCONTENTS:
                                ppk_read_num_contents(fd, rule);
                                printf("n_contents = %ld\n", rule->num_contents);
                                curr_state = PPK_STATE_RCONTENTS;
                                break;
                        case PPK_STATE_RCONTENTS:
                                ppk_read_contents(fd, rule);
                                curr_state = PPK_STATE_RBITMAP;
                                return;
                                break;
                        case PPK_STATE_RBITMAP:
                                ppk_read_bitmap(fd, rule);
                                return;
                                break;
                }               
        }
}

int ppk_automaton(int fd){
        int curr_state = PPK_STATE_RPORTS;
        struct ppk_port_pair* port_pair;
        struct ppk_rule* rule;
        while(1){
                switch (curr_state){
                        case PPK_STATE_RPORTS:
                                port_pair = ppk_read_ports(fd);
                                curr_state = PPK_STATE_RNRULES;
                                break;
                        case PPK_STATE_RNRULES:
                                ppk_read_nrules(fd, port_pair);
                                curr_state = PPK_STATE_RSID;
                                // fill rule
                                ppk_read_rule(fd, rule);
                                return 0;
                                break;
                }
        }

}


int main(){
        int fd = open("sapo_boi_tcp_rules.perereca", O_RDONLY);
        if (fd < 0) exit(-1);

        ppk_automaton(fd);
        int x = 1;

        //printf("%d\n", bitmap << x);
        return 0;
}

