from packet_collecter import PacketCollection
from time import sleep

if __name__ == "__main__":
    sniffer = PacketCollection()
    print("[*] Start sniffing...")
    sniffer.start()
    try:
        while True:
            sleep(100)
    except KeyboardInterrupt:
        print("[*] Stop sniffing...")
        sniffer.join()