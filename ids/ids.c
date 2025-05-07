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
//static bool global_exit;
volatile sig_atomic_t global_exit = 0;
struct xdp_hints_mark xdp_hints_mark = { 0 };
struct port_group_t** port_groups[2];  // uma pra tcp [0] e outra pra udp [1]
FILE* log_file;
int pkt_counter;


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

        printf("global_map_index = %d\n", global_map_index);
        specific_pg = this_port_groups[global_map_index];
        rule = specific_pg->rules[rule_index];
        // se a regra não tem nenhum content, já casou!!
        if(rule->n_contents == 0){
                fprintf(log_file, "(Só o FP) Casou com a regra de sid %d!!!!!\n", rule->sid);
                return;
        }
        //find_remaining_contents(rule, pkt, offset, len);
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
        pkt_counter += stock_frames;

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
                //process_packet(xsk_info, addr, len);

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

/*
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
*/

void rx_and_process(struct config* config, struct xsk_socket_info** xsk_sockets, int n_queues){
        struct pollfd fds[n_queues];  // n_queue vetores de tamanho 1. Essa estrutura é entendida pela syscall poll(), que é usada para verificar se há novos eventos no socket
        for(int i = 0; i < n_queues; i++)
                memset(fds, 0, sizeof(fds));
        int i_queue, rc;

        for(i_queue = 0; i_queue < n_queues; i_queue++){
                fds[i_queue].fd = xsk_socket__fd(xsk_sockets[i_queue]->xsk);
                fds[i_queue].events = POLLIN;  // POLLIN = "there is data to read"
        }

        int ret;
        while(!global_exit){
                ret = poll(fds, n_queues, -1);
                if(ret <= 0)
                        continue;  // nenhum evento
                for(i_queue = 0; i_queue < n_queues; i_queue++){
                        if(fds[i_queue].revents & POLLIN){
                                printf("recebi na fila %d\n", i_queue);
                                handle_receive_packets(xsk_sockets[i_queue]);
                        }
                }
        }
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

        /*
        // inicia as estruturas BTF
        err = init_btf_info_via_bpf_object(bpf_obj, &xdp_hints_mark);
        if (err) {
                fprintf(stderr, "ERROR(%d): Invalid BTF info: errno:%s\n",
                                err, strerror(errno));
                return EXIT_FAILURE;
        }
        */

        if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
                fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
                                strerror(errno));
                exit(EXIT_FAILURE);
        }

        puts("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

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

        // -- XSKS sockets properly configurated. Go wait for packets --
        rx_and_process(&cfg, xsk_sockets, n_queues);

        // Cleanup 
        for (int i_queue = 0; i_queue < n_queues; i_queue++) {
                xsk_socket__delete(xsk_sockets[i_queue]->xsk);
                xsk_umem__delete(umems[i_queue]->umem);
        }
        free(umems);
        free(xsk_sockets);

        printf("pkt_counter = %d\n", pkt_counter);

        //xsk_btf__free_xdp_hint(xdp_hints_mark.xbi);
        bpf_object__close(bpf_obj);

        xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
        return 0;
}

//comando:
//!reset; make; sudo ./remove_maps.sh amigo; sudo ./ids --force --progsec xdp_ids_func -s 0:xdp_inspect_payload --queue 16 --dev amigo -G ./btf.c -H ./btf.c

