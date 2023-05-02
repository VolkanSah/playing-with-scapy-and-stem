# playing-with-scapy-and-stem
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
   #  extract destination IP from user of the evil onion
    def check_destination(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        print(f'Potential intruder detected: {ip_src} -> {ip_dst}')
    # contoller:  keywords
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
