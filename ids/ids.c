#define _GNU_SOURCE  /* Needed by sched_getcpu */
#include <sched.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include "btf.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/socket.h>
#include <sys/syscall.h>
#include <bpf/btf.h> /* provided by libbpf */
#include "common_params.h"
#include "common_user_bpf_xdp.h"
#include "lib_xsk_extend.h"
#include "automaton.h"
#include "common_kern_user.h"


#include "cora.h"
#include "ppk_parser.h"
#include <fcntl.h>

#define NUM_FRAMES         4096 /* Frames per queue */
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE /* 4096 */
#define FRAME_SIZE_MASK    (FRAME_SIZE - 1)
#define RX_BATCH_SIZE      64
#define FQ_REFILL_MAX      (RX_BATCH_SIZE * 2)
#define INVALID_UMEM_FRAME UINT64_MAX

static const struct option_wrapper long_options[] = {

        {{"help",	 no_argument,		NULL, 'h' },
                "Show help", false},

        {{"dev",	 required_argument,	NULL, 'd' },
                "Operate on device <ifname>", "<ifname>", true},

        {{"force",	 no_argument,		NULL, 'F' },
                "Force install, replacing existing program on interface"},

        {{"queue",	 required_argument,	NULL, 'Q' },
                "Configure number of queues to be used for AF_XDP"},

        {{"filename",    required_argument,	NULL,  1  },
                "Load program from <file>", "<file>"},

        {{"progsec",	 required_argument,	NULL,  2  },
                "Load program in <section> of the ELF file", "<section>"},

        {{"tcp-rule-file",	 required_argument,	NULL, 'G' },
                "File containing TCP protocol rules", "tcp.rules"},

        {{"udp-rule-file",	 required_argument,	NULL, 'H' },
                "File containing UDP protocol rules", "udp.rules"},

        {{0, 0, NULL,  0 }, NULL, false}
};

static const char *__doc__ = "AF_XDP kernel bypass example\n";
static char iface_name[16];
volatile sig_atomic_t global_exit = 0;
struct xdp_hints_mark xdp_hints_mark = { 0 };
struct ppk_port_pair** tcp_port_pairs;
struct ppk_port_pair** udp_port_pairs;
FILE* log_file;
int tcp_port_pair_size = 0;
int udp_port_pair_size = 0;

void find_remaining_contents(struct ppk_rule* rule, uint8_t *pkt, int offset, uint32_t len){
        char* begin, *end;
        begin = (char*) (pkt + offset);
        end = (char*) (pkt + len);
        if(!begin || len <= offset)
                return;

        char payload[1024];
        memmove(payload, begin, end-begin);
        printf("%s\n", payload);

        if(ahocora_search(rule->trie, payload, end-begin)){
                printf("aaaaaaaa\n\n");
                fprintf(log_file, "(Com contents) Casou com a regra de sid %d!!!!!\n", rule->sid);
                return;
        }
}

static inline void process_packet(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len){
        uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

        int offset;
        uint32_t global_map_index;
        int16_t rule_index;
        struct ppk_rule* rule;

        offset = is_tcp(pkt, &xdp_hints_mark, &global_map_index, &rule_index) ? 54 : 42;

        printf("global_map_index = %d\n", global_map_index);
        if(global_map_index >= tcp_port_pair_size)
                global_map_index = global_map_index - tcp_port_pair_size; // calcula o indice pro UDP
        if(offset == 42)
                rule = udp_port_pairs[global_map_index]->rules[rule_index];
        else
                rule = tcp_port_pairs[global_map_index]->rules[rule_index];
        // se a regra contém somente 1 content, já casou!!
        if(rule->num_contents == 1){
                fprintf(log_file, "(Só o FP) Casou com a regra de sid %d!!!!!\n", rule->sid);
                return;
        }
        find_remaining_contents(rule, pkt, offset, len);
}

void handle_receive_packets(struct xsk_socket_info* xsk_info){
        uint32_t idx_rx = 0;
        uint32_t idx_fq = 0;
        int ret;
        unsigned int frames_received, stock_frames;

        //recvfrom(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);

        // ver se no RX tem alguma coisa
        frames_received = xsk_ring_cons__peek(&xsk_info->rx, RX_BATCH_SIZE, &idx_rx);  // prenche a var idx_rx
                                                                                       // se não recebeu nada, volta pro loop de pool
        if(!frames_received)
                return;

        // se chegou aqui, recebi pelo menos um pacote nesse socket

        // stock frames é o número de frames recebidos!
        stock_frames = xsk_prod_nb_free(&xsk_info->umem->fq, xsk_info->umem_frame_free);

        if(stock_frames > 0){
                // reserva stock_frames slots no ring fill da UMEM
                ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, stock_frames, &idx_fq);

                // This should not happen, but just in case
                while (ret != stock_frames)
                        ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, frames_received, &idx_fq);

                for(int i = 0; i < stock_frames; i++){
                        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx_fq++) = xsk_alloc_umem_frame(xsk_info);
                }
                xsk_ring_prod__submit(&xsk_info->umem->fq, stock_frames);
        }

        // só agora que vou tratar os pacotes recebidos (!!!!!!!!!)

        uint64_t addr;
        uint32_t len;

        for(int i = 0; i < frames_received; i++){
                // lê o descritor armazenado em idx_rx
                addr = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx)->addr;
                len = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx)->len;
                idx_rx++;

                // função que termina de verificar om pacote (AAAAAAAAAAAAAAAAAAAAAA)
                // process_packet(xsk_info, addr, len);
                printf("pacote len = %d\n", len);
                process_packet(xsk_info, addr, len);

                // adiciona o endereço à lista de endereços disponíveis do fill ring da UMEM
                xsk_free_umem_frame(xsk_info, addr);
        }

        // libera os frames recebidos do RX (indica pro kernel que eu já li essas posições)
        xsk_ring_cons__release(&xsk_info->rx, frames_received);
}

struct thread_struct {
        pthread_t* threads;
        size_t num_threads;
} thread_set;

static void exit_application(int signal){
        printf("exit_app\n\n");
        for(int i = 0; i < thread_set.num_threads; i++){
                pthread_cancel(thread_set.threads[i]);
        }
        signal = signal;
        global_exit = 1;
}

struct thread_args{
        int i_queue;
        struct pollfd* fds;
        struct xsk_socket_info* xsk_socket;
};

void working_thread(void* argument){
        // fds will be size 1
        struct thread_args* args = (struct thread_args*) argument;
        int ret;
        while(!global_exit){
                ret = poll(args->fds, 1, -1);
                if(ret <= 0)
                        continue;  // nenhum evento
                if(args->fds[0].revents & POLLIN){
                        printf("recebi na fila %d\n", args->i_queue);
                        handle_receive_packets(args->xsk_socket);
                }
        }
}

void rx_and_process(struct config* config, struct xsk_socket_info** xsk_sockets, int n_queues){
        struct pollfd fds[n_queues][1];  // n_queue vetores de tamanho 1. Essa estrutura é entendida pela syscall poll(), que é usada para verificar se há novos eventos no socket
        for(int i = 0; i < n_queues; i++)
                memset(fds[i], 0, sizeof(fds[i]));
        int i_queue, rc;

        for(i_queue = 0; i_queue < n_queues; i_queue++){
                fds[i_queue][0].fd = xsk_socket__fd(xsk_sockets[i_queue]->xsk);
                fds[i_queue][0].events = POLLIN;  // POLLIN = "there is data to read"
        }

        // Criando threads para realizar trabalho
        struct thread_args args;
        thread_set.num_threads = n_queues;
        thread_set.threads = malloc(sizeof(pthread_t)*n_queues);
        for(i_queue = 0; i_queue < n_queues; i_queue++){
                args.i_queue = i_queue;
                args.fds = fds[i_queue];
                args.xsk_socket = xsk_sockets[i_queue];
                printf ("Creating thread %d\n", i_queue);
                rc = pthread_create(&(thread_set.threads[i_queue]), NULL, (void*) working_thread, (void*)&args);
                if(rc){
                        printf("Não consegui criar a thread %d. Abortando!!!!\n", i_queue);
                        return;
                }
        }

        for(i_queue = 0; i_queue < n_queues; i_queue++){
                pthread_join(thread_set.threads[i_queue], NULL);
        }
}

/*
static int build_map(int map_fd, struct automaton *dfa){
        struct automaton_map_key map_key;
        int cpus = libbpf_num_possible_cpus();
        struct automaton_map_update_value map_values[cpus];
        struct automaton_transition *map_entries = dfa->entries;

        map_key.padding = 0;
        memset(map_values, 0, sizeof(map_values));

        for (int i = 0; i < dfa->size; i++) {
                map_key.state = map_entries[i].key_state;
                map_key.transition = map_entries[i].key_transition;
                for (int j = 0; j < cpus; j++) {
                        map_values[j].value.state = map_entries[i].value_state;
                        map_values[j].value.leaf = map_entries[i].value_leaf;
                        map_values[j].value.fp__rule_index = map_entries[i].fp__rule_index;
                }
                if (bpf_map_update_elem(map_fd, &map_key, map_values, 0) < 0) {
                        printf("Não foi possivel criar um dos mapa automatos. err(%d):%s\n", errno, strerror(errno));
                        return -1;
                } 
        }
        return 0;
}
*/

/*
int initialize_fast_pattern_port_group_map(int port_map_fd, int* index, uint16_t src, uint16_t dst,
                struct fast_p* fast_patterns_array, size_t len_fp_arr)
{
        char map_name[24];
        struct automaton dfa;

        char pin_dir[32];
        sprintf(pin_dir, "/sys/fs/bpf/%s", iface_name);
        puts(pin_dir);

        // In this moment, every pattern in the port group has been collected, so it's possible to create dfas 
        //build_automaton(fast_patterns_array, len_fp_arr, &dfa);

        // for(int k = 0; k < dfa.entry_number; k++){
        //     printf("entries[%d]:  (%d, %c)  (%d, %d, %d)\n", k, dfa.entries[k].key_state, dfa.entries[k].key_unit, 
        // 		dfa.entries[k].value_state, dfa.entries[k].value_flag, dfa.entries[k].fp__rule_index);
        // }

        struct port_map_key key;
        key.src_port = src;
        key.dst_port = dst;

        // no mapa de portas, cria a chave com base nas duas portas, o valor é o índice no mapa global
        if (bpf_map_update_elem(port_map_fd, &key, index, BPF_ANY) < 0) {
                fprintf(stderr,
                                "ERROR: Failed to update bpf map file: err(%d):%s\n",
                                errno, strerror(errno));
                return -1;
        }

        // pega o mapa correto e adiciona o DFA recém criado
        sprintf(map_name, "ids_map%d", *index);
        printf("\nColocando esse automato no mapa %s  (%d, %d)\n", map_name, src, dst);
        int ids_map_fd = open_bpf_map_file(pin_dir, map_name, NULL);
        if (ids_map_fd < 0) {
                fprintf(stderr,
                                "ERROR: Failed to open bpf ids map: err(%d):%s\n",
                                errno, strerror(errno));
                return -1;
        }
        if (build_map(ids_map_fd, &dfa) < 0) {
                fprintf(stderr,
                                "ERROR: Failed to put dfa on ids map: err(%d):%s\n",
                                errno, strerror(errno));
                return -1;
        }
        free(dfa.entries);
        return 0;
}
*/

static void fill_dfa_map(int index, struct ahocora_trie* trie)
{
        struct ahocora_node* node;
        struct automaton_map_key key;
        struct automaton_map_value value;
        char pin_dir[128], map_name[32];
        sprintf(pin_dir, "/sys/fs/bpf/%s", iface_name);
        int global_map_fd = open_bpf_map_file(pin_dir, "global_map", NULL);
        if(global_map_fd < 0){
                puts("Deu pau na hora de abrir o mapa de mapas");
                return;
        }
        sprintf(map_name, "ids_map%d", index);
        printf("map_name = %s\n", map_name);
        int ids_map_fd = open_bpf_map_file(pin_dir, map_name, NULL);
        if(ids_map_fd < 0){
                 puts("Deu pau na hora de abrir o mapa automato");
                return;
        }
        int cont = 0;
        for(int i = 0; i < trie->size; i++){
                node = trie->array[i];
                for(int j = 0; j < NUM_ACCEPTABLE_SYMBOLS; j++){
                        if(node->basic_links[j] != -1){
                                key.state = node->id;
                                key.transition = j;
                                key.padding = 0;
                                value.state = node->basic_links[j];
                                // leaf vai conter o indice do vetor de regras do par de portas que aponta pra essa regra
                                struct ahocora_node* aux = trie->array[node->basic_links[j]];
                                value.fp__rule_index = (int16_t)aux->rule_sid;
                                //printf("(%d, %c) -> (%d, %d)\n", key.state, key.transition, value.state, value.fp__rule_index);
                                if(bpf_map_update_elem(ids_map_fd, &key, &value, BPF_ANY) < 0){
                                        printf("Problem creating transiction in map (%d, %c) -> (%d, %d)\n", key.state, key.transition, value.state, value.fp__rule_index);
                                        return;
                                }
                                cont++;
                        }
                }
                // colocar o fail link
                if(node->suffix_link > 0){
                        key.state = node->id;
                        key.transition = 0;
                        key.padding = 1;
                        value.state = node->suffix_link;
                        struct ahocora_node* aux = trie->array[node->suffix_link];
                        value.fp__rule_index = (int16_t)aux->rule_sid;

                        if(bpf_map_update_elem(ids_map_fd, &key, &value, BPF_ANY) < 0){
                                printf("Problem creating fail link\n");
                        }
                        //cont++;
                }
                
        }
        printf("Número de entradas no mapa %s ==> %d\n", map_name, cont);
        printf("Size da trie ==> %d\n", trie->size);
}

static void fill_port_maps(int port_map_fd, struct ppk_port_pair** port_pairs, int size)
{
        struct port_map_key key;
        static int count = 0;

        for(int i = 0; i < size; i++){
                key.src_port = port_pairs[i]->src_port[0];
                key.dst_port = port_pairs[i]->dst_port[0];
                if(bpf_map_update_elem(port_map_fd, &key, &count, BPF_ANY) < 0){
                        puts("Problem initializing port map");
                        return;
                }
                printf("Add porta (%d, %d)\n", key.src_port, key.dst_port);
                if(port_pairs[i]->src_port[0] == 0 && port_pairs[i]->dst_port[0] == 25)
                        ahocora_print_trie(port_pairs[i]->fp_trie);
                fill_dfa_map(count, port_pairs[i]->fp_trie);
                count++;
        }
}

int main(int argc, char **argv)
{
        // 25/11
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
        tcp_port_pairs = ppk_automaton (tcp_fd, &tcp_port_pair_size, tcp_rules_array);

        //printf("tcp size = %d\n", tcp_port_pair_size);
        close (tcp_fd);
        /*
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

        return 0;
        getchar();
        */


        int rules_udp_fd = open("rules_udp.perereca", O_RDONLY);
        ppk_read_rule_array_size(rules_udp_fd, &udp_len_array_rules);
        printf("udp_len_array_rules = %d\n", udp_len_array_rules);
        struct ppk_rule** udp_rules_array = malloc(sizeof(struct ppk_rule*) * udp_len_array_rules);
        ppk_automaton_fill_rules_array(rules_udp_fd, udp_rules_array);
        close(rules_udp_fd);

        int udp_fd = open("sapo_boi_udp_rules.perereca", O_RDONLY);
        if (udp_fd < 0)
                exit(-1);
        udp_port_pairs = ppk_automaton (udp_fd, &udp_port_pair_size, udp_rules_array);
        //printf("udp size = %d\n", udp_port_pair_size);
        close (udp_fd);
        /*
        for(int i = 0; i < udp_port_pair_size; i++){
                printf("src = %d -- dst = %d\n", udp_port_pairs[i]->src_port[0], udp_port_pairs[i]->dst_port[0]);
                for (int j = 0; j < udp_port_pairs[i]->num_rules; j++){
                        printf("sid = %d\n", udp_port_pairs[i]->rules[j]->sid);
                }
                puts("");
        }
        */

        printf("Tamanho do vetor mapa de mapas = %d\n", tcp_port_pair_size + udp_port_pair_size);
        ppk_create_ahocora_automata (udp_port_pairs, udp_port_pair_size);
        ppk_create_ahocora_automata (tcp_port_pairs, tcp_port_pair_size);

        ppk_create_ahocora_fp_automata(udp_port_pairs, udp_port_pair_size);
        ppk_create_ahocora_fp_automata(tcp_port_pairs, tcp_port_pair_size);

        int xsks_map_fd;
        struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
        struct config cfg = {
                .do_unload = true,
                .filename = "af_xdp_kern.o",
                .progsec = "xdp",
                .batch_pkts = BATCH_PKTS_DEFAULT,
                .tail_call_map_name = "tail_call_map",
        };
        struct xsk_umem_info **umems;
        struct xsk_socket_info **xsk_sockets;

        cfg.xsk_bind_flags = XDP_COPY;

        struct bpf_object *bpf_obj = NULL;
        struct bpf_map *map;

        struct sigaction action;
        action.sa_handler = exit_application;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        sigaction(SIGINT, &action, NULL);

        parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

        strcpy(iface_name, cfg.ifname);	

        bpf_obj = load_bpf_and_xdp_attach(&cfg);
        if (!bpf_obj) {
                /* Error handling done in load_bpf_and_xdp_attach() */
                exit(EXIT_FAILURE);
        }

        const char* pin_basedir = "/sys/fs/bpf";
        char pin_dir[1024];
        size_t len = snprintf(pin_dir, 1024, "%s/%s", pin_basedir, cfg.ifname);
        if (len < 0) {
                fprintf(stderr, "ERR: creating pin dirname\n");
                return EXIT_FAIL_OPTION;
        }

        printf("\nmap dir: %s\n\n", pin_dir);
        strcpy(cfg.pin_dir, pin_dir);

        pin_maps_in_bpf_object(bpf_obj, &cfg, pin_basedir);

        int err;

        err = set_tail_call_map(bpf_obj, &cfg);
        if (err) {
                fprintf(stderr, "ERR: setting tail call map\n");
                return err;
        }

        // inicia as estruturas BTF
        err = init_btf_info_via_bpf_object(bpf_obj, &xdp_hints_mark);
        if (err) {
                fprintf(stderr, "ERROR(%d): Invalid BTF info: errno:%s\n",
                                err, strerror(errno));
                return EXIT_FAILURE;
        }

        if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
                fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
                                strerror(errno));
                exit(EXIT_FAILURE);
        }

        int tcp_port_map_fd = open_bpf_map_file(pin_dir, "tcp_port_map", NULL);
        if (tcp_port_map_fd < 0) {
                return EXIT_FAIL_BPF;
        }

        int udp_port_map_fd = open_bpf_map_file(pin_dir, "udp_port_map", NULL);
        if (udp_port_map_fd < 0){
                return EXIT_FAIL_BPF;
        }

        int global_map_fd = open_bpf_map_file(pin_dir, "global_map", NULL);
        if (global_map_fd < 0) {
                return EXIT_FAIL_BPF;
        }
        puts("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        fill_port_maps(tcp_port_map_fd, tcp_port_pairs, tcp_port_pair_size);
        fill_port_maps(udp_port_map_fd, udp_port_pairs, udp_port_pair_size);
        return 0;

        // --- At this moment, every possible DFA has been filled. Go handle XSKS --- 

        map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
        xsks_map_fd = bpf_map__fd(map);
        if (xsks_map_fd < 0) {
                fprintf(stderr, "ERROR: no xsks map found: %s\n",
                                strerror(xsks_map_fd));
                exit(EXIT_FAILURE);
        }

        //Configure and initialize AF_XDP sockets  (vetor de ponteiros!!) 
        int n_queues = cfg.xsk_if_queue;
        printf("Número de filas: %d\n\n", n_queues);

        umems = (struct xsk_umem_info **)
                malloc(sizeof(struct xsk_umem_info *) * n_queues);
        xsk_sockets = (struct xsk_socket_info **)
                malloc(sizeof(struct xsk_socket_info *) * n_queues);

        if(!umems || !xsk_sockets){
                printf("Não consegui alocar o vetor de UMEMS ou o vetor de sockets!\n");
        }

        // this function configures UMEMs and XSKs
        if(!af_xdp_init(umems, xsk_sockets, n_queues, &cfg)){
                printf("Tudo certo!!\n");
        }

        // fill xsks map 
        enter_xsks_into_map(xsks_map_fd, xsk_sockets, n_queues);

        log_file = fopen("ids.log", "a");

        // -- XSKS sockets properly configurated. Go wait for packets --
        rx_and_process(&cfg, xsk_sockets, n_queues);

        // Cleanup 
        for (int i_queue = 0; i_queue < n_queues; i_queue++) {
                xsk_socket__delete(xsk_sockets[i_queue]->xsk);
                xsk_umem__delete(umems[i_queue]->umem);
        }
        free(umems);
        free(xsk_sockets);


        xsk_btf__free_xdp_hint(xdp_hints_mark.xbi);
        bpf_object__close(bpf_obj);

        free(thread_set.threads);	
        fclose(log_file);
        xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
        return 0;
}

//comando:
//!reset; make; sudo ./remove_maps.sh amigo; sudo ./ids --force --progsec xdp_ids_func -s 0:xdp_inspect_payload --queue 16 --dev amigo -G ./btf.c -H ./btf.c

