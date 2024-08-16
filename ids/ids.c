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

/*
#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL     69
#endif
#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET     70
#endif
*/

#include <bpf/btf.h> /* provided by libbpf */
#include "common_params.h"
#include "common_user_bpf_xdp.h"
#include "lib_xsk_extend.h"
#include "automaton.h"
#include "common_kern_user.h"

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
static bool global_exit;
struct xdp_hints_mark xdp_hints_mark = { 0 };
struct port_group_t** port_groups[2];  // uma pra tcp [0] e outra pra udp [1]
FILE* log_file;

/*
essa opção permite busy pool
static void __exit_with_error(int error, const char *file, const char *func,
			      int line)
{
	fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func,
		line, error, strerror(error));
	exit(EXIT_FAILURE);
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, __LINE__)

static void apply_setsockopt(struct xsk_socket_info *xsk, bool opt_busy_poll,
			     int opt_batch_size)
{
	int sock_opt;

	if (!opt_busy_poll)
		return;

	sock_opt = 1;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_PREFER_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

	sock_opt = 20;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

	sock_opt = opt_batch_size;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL_BUDGET,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);
}
*/

void find_remaining_contents(struct rule_t* rule, uint8_t *pkt, int offset, uint32_t len){
    char* begin, *end;
    begin = (char*) (pkt + offset);
	end = (char*) (pkt + len);
    if(!begin || len <= offset)
		return;

	char payload[2048];
	memmove(payload, begin, end-begin);
	//printf("%s\n", payload);

	if(process(rule->dfa, payload)){
		printf("aaaaaaaa\n\n");
		fprintf(log_file, "(Com contents) Casou com a regra de sid %d!!!!!\n", rule->sid);
		return;
	}
}

// lógica para receber as info de metadado
// e pegar o autômato correto.
static inline void process_packet(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len){
	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

    int offset;
	uint32_t global_map_index;
	int16_t rule_index;
	struct rule_t* rule;
	struct port_group_t** this_port_groups;
	struct port_group_t* specific_pg;

    offset = is_tcp(pkt, &xdp_hints_mark, &global_map_index, &rule_index) ? 54 : 42;
	this_port_groups = offset == 42 ? port_groups[0] : port_groups[1];
	
	specific_pg = this_port_groups[global_map_index];
	rule = specific_pg->rules[rule_index];
	// se a regra não tem nenhum content, já casou!!
	if(rule->n_contents == 0){
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

        /* This should not happen, but just in case */
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

void rx_and_process(struct config* config, struct xsk_socket_info** xsk_sockets, int n_queues){
    struct pollfd fds[n_queues];  // essa estrutura é entendida pela syscall poll(), que é usada para verificar se há novos eventos no socket
    memset(fds, 0, sizeof(fds));
    int i_queue;

    for(i_queue = 0; i_queue < n_queues; i_queue++){
        fds[i_queue].fd = xsk_socket__fd(xsk_sockets[i_queue]->xsk);
        fds[i_queue].events = POLLIN;  // POLLIN = "there is data to read"
    }

    int ret;
    // fica nesse loop por toda a execução da IDS
    while(!global_exit){
        printf("loop\n");
        // supondo que a IDS rode somente no wake up mode para o FILL ring. Isso significa que o kernel vai ficar dormindo,
        // até que seja acordado // pela IDS. Quando for acordado, o kernel driver usará os endereços da fill ring para 
        //receber os pacotes. O kernel precisa ser devidamente acordado por uma syscall para continuar processando.

        // ret é o número de socket com algum evento (infelizmente não retorna quais os sockets :( 
        ret = poll(fds, n_queues, -1);  // timeout = -1. Sinifica que vai ficar bloqueado até que um evento ocorra.

        if(ret <= 0){
            continue;  // nenhum evento em nenhum socket
        }
        for(i_queue = 0; i_queue < n_queues; i_queue++){
            if(fds[i_queue].revents & POLLIN){
                printf("recebi na fila %d\n", i_queue);
                handle_receive_packets(xsk_sockets[i_queue]);
            }
        }
        

    }
}

static void exit_application(int signal){
	signal = signal;
	global_exit = true;
}

static void create_dfa_per_rule(struct rule_t* rule, char**contents, size_t len_contents){
	rule->dfa = get_ac_automaton(contents, len_contents);
}

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

void check_end_line(char* token){
	size_t len = strcspn(token, "\n");
	if(len == strlen(token))
		return;
	token[len] = '\0';
}

int initialize_fast_pattern_port_group_map(int port_map_fd, int* index, uint16_t src, uint16_t dst,
    struct fast_p* fast_patterns_array, size_t len_fp_arr)
{
    char map_name[24];
    struct automaton dfa;
    
    const char *pin_dir = "/sys/fs/bpf/amigo";  //MUDAR

    /* In this moment, every pattern in the port group has been collected, so it's possible to create dfas */
	build_automaton(fast_patterns_array, len_fp_arr, &dfa);

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

// criar um port_group para cada linha do arquivo
void create_port_groups(struct port_group_t*** this_port_groups, const char* rules_file, int* n_pgs, int global_map_fd, int port_map_fd){
	char line[8192];
	FILE *file;
	char* token, *aux_token;
	char* inner_token, *aux_inner_token, *src_port, *dst_port;
	char* subtoken, *aux_subtoken;
	struct port_group_t* current_port_group;
	struct rule_t* rule;
	int rule_index = 0, pgs_index = *n_pgs;
	uint32_t sid;
	int M = 500;
	int N = 500;

	struct fast_p fast_patterns_array[300];
	size_t index_fp = 0;

	char* rule_contents[600];
	int index_rule_contents = 0;

	file = fopen(rules_file, "r");
	if (file == NULL) {
		printf("Error opening file!\n");
		return;
	}
	if(*this_port_groups == NULL){
		*this_port_groups = (struct port_group_t**)malloc(sizeof(struct port_group_t*)*M);
		if(*this_port_groups == NULL){
			printf("Error allocating memory!\n");
			return;
		}
	}

	while(fgets(line, 8192, file)){
		token = __strtok_r(line, "~", &aux_token);  // these are the src and dst ports
		current_port_group = (struct port_group_t*)malloc(sizeof(struct port_group_t));

		if(pgs_index >= M){
			M = M + 100;
			*this_port_groups = (struct port_group_t**)realloc(*this_port_groups, sizeof(struct port_group_t*)*M);
		}

    	current_port_group->n_rules = 0;
		inner_token = __strtok_r(token, ";", &aux_inner_token);
		src_port = inner_token;
		if(strcmp(src_port, "any") == 0)
			current_port_group->src_port = 0;
		else
			current_port_group->src_port = atoi(src_port);
		inner_token = __strtok_r(NULL, ";", &aux_inner_token);
    	dst_port = inner_token;
		if(strcmp(dst_port, "any") == 0)
			current_port_group->dst_port = 0;
		else
			current_port_group->dst_port = atoi(dst_port);

		current_port_group->rules = (struct rule_t**)malloc(sizeof(struct rule_t*)*N);

		token = __strtok_r(NULL, "~", &aux_token);

		while(token != NULL){  // start to parse the actual rules
			// Needs to realloc
			if (current_port_group->n_rules >= N){
				N = N + 50;
				current_port_group->rules = (struct rule_t**)realloc(current_port_group->rules, sizeof(struct rule_t*)*N);
			}

			rule = (struct rule_t*)malloc(sizeof(struct rule_t));
			rule->n_contents = 0;

			inner_token = __strtok_r(token, ";", &aux_inner_token);

			// add fp in array
			fast_patterns_array[index_fp].fp = inner_token;

			inner_token = __strtok_r(NULL, ";", &aux_inner_token);
      		check_end_line(inner_token);  // remove '\n'
			sid = atoi(inner_token);

			rule->sid = sid;

			inner_token = __strtok_r(NULL, ";", &aux_inner_token);
			if(inner_token){
				subtoken = __strtok_r(inner_token, ",", &aux_subtoken);
				while(subtoken != NULL){
					check_end_line(subtoken);  // remove '\n'
					rule_contents[index_rule_contents++] = subtoken;
					rule->n_contents++;
					subtoken = __strtok_r(NULL, ",", &aux_subtoken);
				}
			}
			else{
				rule->n_contents = 0;
			}

			// aqui, já tenho todos os contents da regra no vetor rule_contents (vetor de strings)
			// preencher o automato pra esses contents
			if(index_rule_contents > 0){
				create_dfa_per_rule(rule, rule_contents, index_rule_contents);
			}
			fast_patterns_array[index_fp].idx = rule_index;
			index_fp++;

			current_port_group->rules[rule_index] = rule;
			
			rule_index++;
			current_port_group->n_rules++;
			index_rule_contents = 0;

			token = __strtok_r(NULL, "~", &aux_token);
		}
    	(*this_port_groups)[pgs_index] = current_port_group;
  		rule_index = 0;

        if (initialize_fast_pattern_port_group_map(port_map_fd, &pgs_index, current_port_group->src_port,
                current_port_group->dst_port, fast_patterns_array, index_fp) < 0) {
            printf("Não consegui criar os grupos de portas -- err(%d):%s\n",
                errno, strerror(errno));
            return;
        }
		pgs_index++;
		index_fp = 0;

	}
    fclose(file);
	*n_pgs = pgs_index;
}

void destroy_port_groups(struct protocol_port_groups_t* protocol_port_group){
	for(ssize_t i = 0; i < protocol_port_group->n_port_groups; i++){
		for (ssize_t j = 0; j < protocol_port_group->port_groups_array[i]->n_rules; j++){
			free(protocol_port_group->port_groups_array[i]->rules[j]);
		}
        free(protocol_port_group->port_groups_array[i]->rules);
		free(protocol_port_group->port_groups_array[i]);
	}
	free(protocol_port_group->port_groups_array);
}


int main(int argc, char **argv)
{
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

    /* Global shutdown handler */
	signal(SIGINT, exit_application);

    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

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


	// haverá um vetor de grupos de portas, contendo os fast patterns de TCP e UDP
	// representação fiel do mapa global_map
	int num_port_groups = 0;
	struct protocol_port_groups_t port_groups_array;
	struct port_group_t** pg_array = NULL;
	const char* udp_fast_ptts = cfg.udp_rule_inter;
	const char* tcp_fast_ptts = cfg.tcp_rule_inter;
	printf("ARQ TCP = %s\n", cfg.tcp_rule_inter);
	printf("ARQ UDP = %s\n", cfg.udp_rule_inter);

	create_port_groups(&pg_array, udp_fast_ptts, &num_port_groups,
        global_map_fd, udp_port_map_fd);
    if (pg_array == NULL) {
		printf("Não alocou memória pra o vetor de grupos. Saindo.");
		return EXIT_FAIL_BPF;
	}
	port_groups_array.port_groups_array = pg_array;
	port_groups_array.n_port_groups = num_port_groups;

	printf("UDP port_groups_array size = %ld\n", port_groups_array.n_port_groups);
	port_groups[1] = port_groups_array.port_groups_array;

	create_port_groups(&pg_array, tcp_fast_ptts, &num_port_groups,
        global_map_fd, tcp_port_map_fd);

	port_groups_array.port_groups_array = pg_array;
	port_groups_array.n_port_groups = num_port_groups;

	printf("TCP port_groups_array size = %ld\n", port_groups_array.n_port_groups);
	port_groups[0] = port_groups_array.port_groups_array;


    /* --- At this moment, every possible DFA has been filled. Go handle XSKS --- */

    map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
    xsks_map_fd = bpf_map__fd(map);
    if (xsks_map_fd < 0) {
        fprintf(stderr, "ERROR: no xsks map found: %s\n",
            strerror(xsks_map_fd));
        exit(EXIT_FAILURE);
    }

    /* Configure and initialize AF_XDP sockets  (vetor de ponteiros!!) */
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

    /* fill xsks map */
    enter_xsks_into_map(xsks_map_fd, xsk_sockets, n_queues);

	log_file = fopen("ids.log", "a");

	/* -- XSKS sockets properly configurated. Go wait for packets --*/

    rx_and_process(&cfg, xsk_sockets, n_queues);

    /* Cleanup */
	for (int i_queue = 0; i_queue < n_queues; i_queue++) {
		xsk_socket__delete(xsk_sockets[i_queue]->xsk);
		xsk_umem__delete(umems[i_queue]->umem);
	}
    free(umems);
    free(xsk_sockets);
    destroy_port_groups(&port_groups_array);

	fclose(log_file);

	xsk_btf__free_xdp_hint(xdp_hints_mark.xbi);
	bpf_object__close(bpf_obj);	

    xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
    return 0;
}
