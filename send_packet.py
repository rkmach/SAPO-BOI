from scapy.all import TCP, IP, Raw, sendp, Ether, IFACES, UDP, wrpcap

data = 'sCachorrRETRodqwertyytrewq0ioSERdd'
a = Ether() / IP(src='10.11.1.2', dst='10.11.1.1') / TCP(sport=23, dport=21) / Raw(load=data)
iface = IFACES.dev_from_name("veth0")
sendp(a, iface=iface)

