from scapy.all import sniff, IP, TCP, UDP
import csv
import datetime
import pyfiglet
import sys
import socket

target_ip = str(input("\nEnter the target IP: "))
count = int(input("Number of packets to be captured: "))
first_port = int(input("First port to be scanned: "))
last_port = int(input("Last port to be scanned: "))

log_file = "packet_log.csv"

# Creating a CSV file
with open(log_file, 'a', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Packet Info"])

def packet_callback(packet):
    try:
        if packet.haslayer(IP):
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            # Identification of the protocols
            if packet.haslayer(TCP):
                protocol_type = 'TCP'
            elif packet.haslayer(UDP):
                protocol_type = 'UDP'
            else:
                protocol_type = f'Protocol {protocol}'

            # Logging packet details into to the CSV file
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            packet_info = f"Source: {source_ip} -> Destination: {dest_ip} | Protocol: {protocol_type}"
            
            with open(log_file, 'a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([timestamp, source_ip, dest_ip, protocol_type, packet_info])
            
            print(f"{timestamp} | {packet_info}")

            # Example of ALERT for unencrypted HTTP traffic
            # if protocol_type == 'TCP' and packet.haslayer(TCP) and packet[TCP].dport == 80:
            #     print(f"\nALERT: Unencrypted HTTP traffic detected from {source_ip} to {dest_ip}\n")

            if protocol_type == 'TCP' and packet.haslayer(TCP):
                if packet[TCP].dport == 80:
                    print(f"\nALERT: Unencrypted HTTP traffic detected from {source_ip} to {dest_ip}\n")
                elif packet[TCP].dport == 21:
                    print(f"\nALERT: Unencrypted FTP traffic detected from {source_ip} to {dest_ip}\n")
                elif packet[TCP].dport == 23:
                    print(f"\nALERT: Unencrypted Telnet traffic detected from {source_ip} to {dest_ip}\n")
                elif packet[TCP].dport == 25:
                    print(f"\nALERT: Unencrypted SMTP traffic detected from {source_ip} to {dest_ip}\n")
                elif packet[TCP].dport == 110:
                    print(f"\nALERT: Unencrypted POP3 traffic detected from {source_ip} to {dest_ip}\n")
                elif packet[TCP].dport == 143:
                    print(f"\nALERT: Unencrypted IMAP traffic detected from {source_ip} to {dest_ip}\n")

                if protocol_type == 'UDP' and packet.haslayer(UDP):
                    if packet[UDP].dport == 161:
                        print(f"\nALERT: Unencrypted SNMP traffic detected from {source_ip} to {dest_ip}\n")

            
    except Exception as e:
        print(f"Error processing packet: {e}")

# Sniffing packets with a limit and storing them in real-time
print(f"Starting packet sniffing, capturing {count} packets...")
sniff(filter="ip", prn=packet_callback, count=count, store=0)

print(f"\nFetched data is stored in {log_file}")

# port scanner 

ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
print(ascii_banner)

if len(sys.argv) == 2:
	
	# translating hostname to IPv4
	target_ip = socket.gethostbyname(sys.argv[1])

# For banner 
print("-" * 50)
print("Target IP: " + target_ip)
print("Port scanning: " + f"{first_port} to {last_port}")
print("-" * 50)

try:
	
	# will scan ports between first_port to last_port
    for port in range(first_port,last_port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
		
        result = s.connect_ex((target_ip,port))
        if result ==0:
            print(f"Port {port} is open")
        s.close()
		
# Error handling        
except KeyboardInterrupt:
		print("\n Exiting Program !!!!")
		sys.exit()
except socket.gaierror:
		print("\n Hostname Could Not Be Resolved !!!!")
		sys.exit()
except socket.error:
		print("\ Server not responding !!!!")
		sys.exit()

# 50.87.253.113
# 100.115.35.154
# 184.168.115.128
# 172.217.27.163
# 20.192.1.43

# PayPal account credentials:

# e-mail: bahaikahamdebbarma704@gmail.com
# passwd: gtefti7err2451vz32t4