run:a.out
	sudo ./a.out

build:a.out
        

a.out:loader.c xdp_drop.o
	gcc -lxdp -lbpf loader.c

xdp_drop.o:xdp_drop.c
	clang -O2 -g -Wall -target bpf -c xdp_drop.c -o xdp_drop.o
clean:
	sudo ip link set eno1 xdpgeneric off
	rm -f a.out xdp_drop.o
