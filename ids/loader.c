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
#include <sys/resource.h>

#include "xsk_socket.h"
#include "common_defines.h"
#include <poll.h>
//#include <pcap.h>
//#include <time.h>

struct xdp_program * prog;
// Sobrescrever a seguinte variável com o índice da interface desejada
int ifindex = 7;
int n_queues = 1;
int global_exit = 0;

//pcap_t *pcap_handle;
//pcap_dumper_t *file_pcap;

static void exit_application(int sig)
{
        xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);
        xdp_program__close(prog);
        // Sai do laço principal do programa
        global_exit = 1;
}

static inline void handle_receive_packets(struct xsk_socket_info* xsk_info){
        uint32_t idx_rx = 0;
        uint32_t idx_fq = 0;
        int ret;
        unsigned int frames_received, stock_frames;

        // ver se no RX tem alguma coisa
        frames_received = xsk_ring_cons__peek(&xsk_info->rx, RX_BATCH_SIZE, &idx_rx);  // prenche a var idx_rx
                                                                                       // se não recebeu nada, volta pro loop de pool
        if(!frames_received)
                return;

        // se chegou aqui, recebi pelo menos um pacote nesse socket
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

                uint8_t *pkt = xsk_umem__get_data(xsk_info->umem->buffer, addr);

                //COLOCANDO O PACOTE NUM PCAP
                /*
                pcap_handle = pcap_open_dead(1, 65535);
                file_pcap = pcap_dump_open(pcap_handle, "teste.pcap");
                if (file_pcap == NULL) {
                        fprintf(stderr, "Error opening savefile: %s\n", pcap_geterr(pcap_handle));
                        return;
                }

                struct pcap_pkthdr header;
                gettimeofday(&header.ts, NULL); // Current timestamp
                header.caplen = len;    // Length of portion present in file
                header.len = len;       // Actual length of packet on wire

                puts("111");
                pcap_dump((u_char*)file_pcap, &header, pkt);
                puts("222");

                pcap_dump_close(file_pcap);
                pcap_close(pcap_handle);
                */

                // adiciona o endereço à lista de endereços disponíveis do fill ring da UMEM
                xsk_free_umem_frame(xsk_info, addr);
        }

        // libera os frames recebidos do RX (indica pro kernel que eu já li essas posições)
        xsk_ring_cons__release(&xsk_info->rx, frames_received);
}

int main ()
{
        struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
        // Definindo que não há limites de memória para a execução deste programa
        if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
                return -1;
        }

        struct sigaction action;
        action.sa_handler = exit_application;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        sigaction(SIGINT, &action, NULL);

        struct config cfg = {
                .do_unload = true,
                //.filename = "af_xdp_kern.o",
                .filename = "xdp_redirect.o",
                .progsec = "xdp",
                .batch_pkts = BATCH_PKTS_DEFAULT,
        };

        cfg.xsk_bind_flags = XDP_COPY;
        cfg.ifname = "microsec";
        cfg.ifindex = 7;

        //prog = xdp_program__open_file("af_xdp_kern.o", "xdp", 0);
        prog = xdp_program__open_file("xdp_redirect.o", "xdp", 0);

        if (!prog)
        {
                printf ("xdp_program__open_file error");
                return 1;
        }


        int ret = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0);
        if (ret) {
                printf ("xdp_program__attach error");
                return ret;
        }


        struct bpf_object *bpf_obj = xdp_program__bpf_obj(prog);

        struct bpf_map *map;
        map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");

        int xsks_map_fd;
        xsks_map_fd = bpf_map__fd(map);
        if (xsks_map_fd < 0) {
                fprintf(stderr, "ERROR: no xsks map found: %s\n",
                                strerror(xsks_map_fd));
                exit(EXIT_FAILURE);
        }

        //Configure and initialize AF_XDP sockets  (vetor de ponteiros!!)

        struct xsk_umem_info **umems;
        struct xsk_socket_info **xsk_sockets;

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

        // ATÉ AQUI EU SÓ CRIEI O MAPA DE REDIRECT (SEM PINNAR!) E O  PREENCHI.
        return 0;

        // Primeiro, faz polling pra receber na UMEM
        struct pollfd fds[n_queues];  // Essa estrutura é entendida pela syscall poll(), que é usada para verificar se há novos eventos no socket
        for(int i = 0; i < n_queues; i++)
                memset(fds, 0, sizeof(fds));
        int i_queue;

        for(i_queue = 0; i_queue < n_queues; i_queue++){
                fds[i_queue].fd = xsk_socket__fd(xsk_sockets[i_queue]->xsk);
                fds[i_queue].events = POLLIN;  // POLLIN = "there is data to read"
        }

        while(!global_exit){
                ret = poll(fds, n_queues, -1);
                if(ret <= 0)
                        continue;  // nenhum evento
                for(i_queue = 0; i_queue < n_queues; i_queue++){
                        if(fds[i_queue].revents & POLLIN){
                                printf("recebi na fila %d\n", i_queue);
                                // Nessa função, salvo pacotes redirecionados num pcap
                                handle_receive_packets(xsk_sockets[i_queue]);
                        }
                }
        }

        // Cleanup
        for (int i_queue = 0; i_queue < n_queues; i_queue++) {
                xsk_socket__delete(xsk_sockets[i_queue]->xsk);
                xsk_umem__delete(umems[i_queue]->umem);
        }
        free(umems);
        free(xsk_sockets);

        return 0;
}

