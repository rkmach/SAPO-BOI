'''
from scapy.all import TCP, IP, Raw, sendp, Ether, IFACES, UDP, wrpcap

data = 'sCachorrodqwertyytrewq0ioSERdd'
a = Ether() / IP(src='10.11.1.2', dst='10.11.1.1') / UDP(sport=23, dport=32) / Raw(load=data)
iface = IFACES.dev_from_name("veth0")
sendp(a, iface=iface)
'''

import requests

# Make a GET request to a URL
response = requests.get('https://api.github.com/users/mimo-org', iface='veth0')

# Check the status code (200 means success)
if response.status_code == 200:
    # Access the response content
    print(response.text)
    #data = response.json()
    #print(f"Public repos: {data['public_repos']}")
else:
    print(f"Error: Status code {response.status_code}")

