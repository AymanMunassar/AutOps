
"""
ServiceSniffer is a python script used to sniff local services running on your server
It is doing this by monitoring server TCP sessions and count the number of packets. 
A timestamp, TCP port and number of packets are stored in an XML file every 59s by default.
You can utilize these data to pull it and store it in a DB to be displayed in a graph and monitored by NOC team.

Prerequists: install scapy by running pip install scapy
"""

# Written by Ayman Munassar


import xml.etree.ElementTree as ET
import time
from scapy.all import *
import threading

dest_ip = "127.0.0.1" #Change me - IP to monitor
tcp_ports = [443, 80, 22, 53] #Change me - Ports to monitor
timer = 59 # Change me - Refresh in seconds
data = []
results = {}


def count_packets(port):
    #You can mnipulate the filter as you need with Berkeley Packet Filter (BPF)
    packets = sniff(filter=f"ip host {dest_ip} and tcp port {port}", timeout=timer)
    return len(packets)

def save_to_xml():
    file_path =  "Packet_Counter.xml"
    root = ET.Element("Packet_Counts")
    for entry in data:
        packet = ET.SubElement(root, "Counter_Info")
        packet.set("Timestamp", entry["timestamp"])
        allTuples = list(entry.items())
        secondTuple = allTuples[1:2]
        
        for port, count in secondTuple:
            port_elem = ET.SubElement(packet, "Port")
            port_elem.set("Number", str(port).rsplit('_', 1)[1])
            port_elem.set("Packet_count", str(count))
    
    tree = ET.ElementTree(root)
    tree.write(file_path)

def threadedCounting():
    data.clear()
    threads = []
    for port in tcp_ports:
        thread = threading.Thread(target=lambda res, f, val: res.update({f.__name__ + "_" + str(val): f(val)}), args=(results, count_packets , port))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    for key, value in results.items():
        data.append({"timestamp":time.ctime(),key:value})

def main():
    while True:
        threadedCounting()
        save_to_xml()
        time.sleep(1)

if __name__ == "__main__":
    main()
