## Instalar requisitos

        sudo apt install clang llvm libelf-dev gcc-multilib

## Configurar e Compilar
Este passo compilará e instalará as bibliotecas `libbpf` e `libxdp`, fundamentais para o funcionamento do sistema.

        ./configure
        make

## Execução

 - Trocar de diretório:

        cd ids/
 - Limpar mapas existentes:

        sudo ./remove_maps.sh <nome_da_interface>
 - Executar o sistema (caso o driver da sua placa de rede possua suporte a execução de programas XDP. Lista de drivers: https://ebpf-docs.dylanreimerink.nl/linux/program-type/BPF_PROG_TYPE_XDP/#driver-support):

        sudo ./ids --force --progsec xdp_ids_func -s 0:xdp_inspect_payload --queue $(nproc) --dev <nome_da_interface> -G ./r_1_tcp.rules -H ./r_1_udp.rules
 -  Caso você não queira instanciar o sistema na interface real, ou a sua placa de rede não possua suporte ao XDP, você pode criar uma interface virtual e acoplar a solução nela seguindo os passos a seguir:

        Crie um `alias` para o script que define novas interfaces virtuais:
        > eval $(./testenv/testenv.sh alias)
        A seguir, defina uma nova interface:
        > t setup --name <nome_da_interface> --legacy-ip --vlan
        O script criará a interface e tentará verificar se está tudo certo por meio do comando `ping`. Caso não funcione, execute o comando abaixo e depois novamente o comando acima.
        > t teardown --name <nome_da_interface_virtual>

        Com a interface virtual criada corretamente, execute o sistema da seguinte maneira:
        > sudo ./remove_maps.sh <nome_da_interface_virtual>
        > sudo ./ids --force --progsec xdp_ids_func -s 0:xdp_inspect_payload --queue 1 --dev <nome_da_interface_virtual> -G ./r_1_tcp.rules -H ./r_1_udp.rules

        Note que deve haver apenas uma fila configurada, e consequentemente apenas 1 socket XDP.

        Para enviar pacotes para a interface virtual, abra um novo terminal, vá até o diretório deste projeto e digite:
        > eval $(./testenv/testenv.sh alias)
        > t enter <nome_da_inetrface_virtual>
        > python send_packet.py  (configure esse script para forjar o pacote da maneira que quiser)
        
	
	O script para criar as interfaces virtuais, bem como a interpretação de argumentos do programa e algumas interfaces com as bibliotecas libbpf e libxdp foram baseados no XDP tutorial (https://github.com/xdp-project/xdp-tutorial).	

