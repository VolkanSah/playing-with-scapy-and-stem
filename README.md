# playing with scapy and stem
###### [Volkan Sah](https://github.com/volkansah) 
https://stem.torproject.org/api.html
no explanation to give malicious users no dangerous script in their hands, want help me please?
## the idea, 
it is only an idea for the head of a MasterCode in TerminalApp 
```python
from scapy.all import *
import csv
import time
import re
import stem.control
import stem
from stem.control import Controller
from stem import StreamListener
# set controller
with Controller.from_port(port=9051) as controller:
    controller.authenticate()
# set Stream Listener
class MaliciousTrafficListener(StreamListener):
    def __init__(self, keywords):
        self.keywords = keywords

    def stream_new(self, stream):
        if any(re.search(keyword, stream.target_host) for keyword in self.keywords):
            print(f"Malicious traffic detected to {stream.target_host}")
   #  extract destination IP from user of the evil 
    #def check_destination(pkt):
   # if IP in pkt:
      #  ip_src = pkt[IP].src
      #  ip_dst = pkt[IP].dst
      #  print(f'Potential intruder detected: {ip_src} -> {ip_dst}')
    # contoller:  keywords e.g abuse, crime...
    with Controller.from_port(port=9051) as controller:
    controller.authenticate()
    controller.add_event_listener(MaliciousTrafficListener(["abuse", "crime"]))
    input("Press Enter to exit")

    # authenticat
    with stem.control.Controller.from_port() as controller:
    controller.authenticate()

    # Get the current circuit and its hops
    circuit_id = controller.get_circuit_id()
    hops = controller.get_circuit(circuit_id).path

    # Add malicious relays to circuit blacklist
    for hop in hops:
        if hop.fingerprint in malicious_relays:
            controller.set_conf(f"ExcludeExitNodes {hop.fingerprint}")
```

example 2: 
```
from scapy.all import *
from stem import Signal
from stem.control import Controller
import requests

def check_if_tor_traffic(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 443:
        with Controller.from_port(port = 9051) as controller:
            controller.authenticate()
            if controller.get_info("address") == packet[IP].dst:
                return True
    return False

def sniff_packets():
    packets = sniff(filter="tcp and (port 9050 or port 9051)", prn=check_if_tor_traffic)

def intercept_api_requests(request):
    if sniff_packets():
        # This is where you would load and execute your external script.
        # Remember that executing code fetched from the internet can be risky.
        external_script_url = "https://example.com/external_script.py"
        response = requests.get(external_script_url)
        if response.status_code == 200:
            exec(response.text)
        else:
            print("Failed to load the external script.")
``` 





```

### Idea by, still yet
- [VolkanSah on Github](https://github.com/volkansah)
- [Developer Site](https://volkansah.github.io)
- [Become a 'Sponsor'](https://github.com/sponsors/volkansah)
