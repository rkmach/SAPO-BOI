from scapy.all import TCP, IP, Raw, sendp, Ether, IFACES, UDP, wrpcap
import random

methods = ['GET', 'POST', 'HEAD']
lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus facilisis ipsum sit amet tempus vestibulum. Nunc aliquam lectus non aliquam molestie. Quisque nec porttitor massa, rutrum aliquam velit. Nam in convallis ante. Suspendisse potenti. Praesent blandit consectetur quam, ultrices congue urna lobortis ut. Proin semper lacus imperdiet orci euismod, vel dapibus felis porttitor. Curabitur porttitor vestibulum lacinia. Sed ac molestie augue, vel varius augue. Etiam eu enim orci.Fusce ut felis varius, auctor diam vel, dictum purus. Morbi elementum mauris leo, sed vestibulum lacus ultricies at. Etiam augue lacus, volutpat sed aliquet eu, tincidunt sed lorem. Donec in elementum purus. Donec tempus non turpis a lacinia. Donec suscipit justo nec enim tempus dictum. Sed laoreet sagittis purus vel sollicitudin. Integer tempor et arcu sed aliquet.Vestibulum tempus aliquet nisi, in vehicula dui rhoncus et. Suspendisse fringilla consequat dolor sit amet ultricies. Suspendisse pulvinar turpis ante, sit amet ullamcorper ex molestie eu. Donec a lorem at augue porta hendrerit at porta eros. In tincidunt ultricies tortor ac vehicula. In purus ex, viverra sit amet mauris ac, ultricies ornare velit. Vestibulum sagittis tempor felis. Suspendisse malesuada nulla venenatis, blandit dolor eu, elementum dolor. Mauris id aliquet lectus, eu auctor turpis. Praesent facilisis tempor neque, ac leo."
for i in range(1000*1000):
    data = methods[random.randint(0, 2)] + lorem
    a = Ether() / IP(src='10.11.1.2', dst='10.11.1.1') / TCP(sport=23, dport=32) / Raw(load=data)
    wrpcap("validationBPF2.pcap", a, append=True)

'''
iface = IFACES.dev_from_name("veth0")
sendp(a, iface=iface)
'''

