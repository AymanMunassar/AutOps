
"""
ServiceSniffer is a python script used to sniff local services running on your server
It is doing this by monitoring server TCP sessions and count the number of packets. 
A timestamp, TCP port and number of packets are stored in an XML file every 59s by default.
You can utilize these data to pull it and store it in a DB to be displayed in a graph and monitored by NOC team.

Prerequists: install scapy by running pip install scapy
"""

# Written by Ayman Munassar


import json
import time
import socket
import struct
import threading

target_ip = "127.0.0.1" #Change me - IP to monitor
tcp_ports = [10000, 10001, 10002, 10003, 10004, 10005] #Change me - Ports to monitor
timer = 59 # Change me - Refresh in seconds
interface = 'eth0' # Change me - Interface to monitor
data = []
results = {}

def count_sms(port):
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))#socket.htons(3) = ipv4 
    conn.bind((interface, 0))
    packet_count = 0
    timeout = time.time() + timer
    while time.time() < timeout:
        raw_data, _ = conn.recvfrom(65535)
        # Parsing Ethernet
        dest_mac, src_mac, eth_proto = struct.unpack('!6s6sH', raw_data[:14])
        #src_mac_str = ':'.join(format(x, '02x') for x in src_mac)
        #dest_mac_str = ':'.join(format(x, '02x') for x in dest_mac)
        if dest_mac[0] & 1 == 0:
            #Parsing IP
            ip_header = raw_data[14:34]
            #ip_header_length = (ip_header[0] & 15) * 4
            src_ip = socket.inet_ntoa(ip_header[12:16])
            #dest_ip = socket.inet_ntoa(ip_header[16:20])
            if src_ip == target_ip: #or dest_ip == target_ip:
                #Parsing TCP
                tcp_header = struct.unpack('!HHLLBBHHH', raw_data[34:54])
                source_port, dest_port = tcp_header[0], tcp_header[1]
                if dest_port == port: #or dest_port == port:
                    packet_count += 1
    return packet_count

def save_to_json(data):
    file_path = "SMS_Counter.json"
    result =  {"SMS_Counts": []}
    #print(data)
    for entry in data:
        allTuples = list(entry.items())
        secondTuple = allTuples[1:2]
        for port, count in secondTuple:
            timestamp = int(entry["timestamp"])
            count = str(count)
            port = str(port).rsplit('_', 1)[1]
            packet = {
                "Port": port,
                "Counter_Info": {
                    "Timestamp": timestamp,
                    "Count": count
                }
            }
        result["SMS_Counts"].append(packet)
    
    with open(file_path, 'w') as file:
        json.dump(result, file, indent=4)

def threadedCounting():
    data.clear()
    threads = []
    for port in tcp_ports:
        thread = threading.Thread(target=lambda res, f, val: res.update({f.__name__ + "_" + str(val): f(val)}), args=(results, count_sms , port))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    for key, value in results.items():
        data.append({"timestamp":int(time.time()),key:value})

def main():
    while True:
        threadedCounting()
        save_to_json(data)
        time.sleep(1)
        
if __name__ == "__main__":
    main()
