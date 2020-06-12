
from scapy.all import sniff
from scapy.all import IP
from scapy.all import Raw
from scapy.all import TCP
from scapy.all import hexdump
from scapy.utils import sane_color
from threading import Thread
from time import sleep
import location_request
import requests


class PacketCollection(Thread):
    def __init__(self):
        super().__init__()
    
    def run(self):
        sniff(prn=self.print_packet)
        #sniff(prn=self.post_request)
        
    def hexdump(self, x):
        x=str(x)
        l = len(x)
        i = 0
        while i < l:
            print("%04x  " % i)
            for j in range(16):
                if i+j < l:
                    print("%02X" % ord(x[i+j]))
                else:
                    print("  ")
                if j%16 == 7:
                    print("")
            print(" ")
            print(sane_color(x[i:i+16]))
            i += 16
    
    def get_IP(self, packet):
        ip_layer = packet.getlayer(IP)
        return ip_layer
        
    def get_Raw(self, packet, default=True):
        raw_layer = packet.getlayer(Raw)
        if raw_layer is None:
            return 'None'
        if default:
            hexdump(raw_layer.load)
        return ""
    
    def get_TCP(self, packet):
        tcp_layer = packet.getlayer(TCP)
        return tcp_layer
        
    def print_packet(self, packet):
        time.sleep(1)
        ip= self.get_IP(packet)    
        raw= self.get_Raw(packet)
        
        src_loc = "Unknown"
        dst_loc = "Unknown"
        if ip != None:
            src_loc = location_request.get_cityAddr_tup(location_request.parse_IP(ip.src))
            dst_loc = location_request.get_cityAddr_tup(location_request.parse_IP(ip.dst))
        
        print("[!] New Packet:")
        if ip != None:
            print("[!] {src} -> {dst}".format(src=ip.src, dst=ip.dst))
        print("[!] {src} -> {dst}".format(src=src_loc, dst=dst_loc))
        print("[!] Hexdumped: {raw}".format(raw=raw))
        
        print("[!]")
        
    def post_request(self, packet):
        time.sleep(1)
        ip= self.get_IP(packet)
        #raw= self.get_Raw(packet)
        src_loc = str(location_request.get_cityAddr_tup(location_request.parse_IP(ip.src)))
        dst_loc = str(location_request.get_cityAddr_tup(location_request.parse_IP(ip.dst)))
        src_coor = str(location_request.get_coor_tup(location_request.parse_IP(ip.src)))
        dst_coor = str(location_request.get_coor_tup(location_request.parse_IP(ip.dst)))
        
        url = "http://127.0.0.1:8000/bloodhound/"
        
        payload={"src_ip":str(ip.src), 
                 "dst_ip":str(ip.dst), 
                 "src_loc":src_loc, 
                 "dst_loc":dst_loc, 
                 "src_coor":src_coor, 
                 "dst_coor":dst_coor
                 }
        
        r = requests.post(url, data=payload)
        
        
        
        
        
        
