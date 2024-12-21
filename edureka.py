from scapy.all import sniff, IP, TCP, UDP
from collections import Counter
from datetime import datetime

# Globalni brojači
protocol_counter = Counter()
ip_counter = Counter()
port_counter = Counter()

def packet_handler(packet):
    """
    Obrada svakog uhvaćenog paketa i analiza njegovih osnovnih karakteristika.
    """
    try:
        # Brojanje po protokolu
        if IP in packet:
            protocol_counter[packet[IP].proto] += 1
            ip_counter[packet[IP].src] += 1
            ip_counter[packet[IP].dst] += 1

        # Analiza TCP/UDP saobraćaja
        if TCP in packet:
            port_counter[packet[TCP].sport] += 1
            port_counter[packet[TCP].dport] += 1
        elif UDP in packet:
            port_counter[packet[UDP].sport] += 1
            port_counter[packet[UDP].dport] += 1
    except Exception as e:
        print(f"Greška prilikom obrade paketa: {e}")

def display_summary():
    """
    Ispisuje sažetak uhvaćenog mrežnog saobraćaja.
    """
    print("\n[INFO] Analiza završena. Rezultati:")
    print("\nProtokoli:")
    for proto, count in protocol_counter.items():
        print(f"  Protokol {proto}: {count} paketa")

    print("\nIP adrese sa najviše aktivnosti:")
    for ip, count in ip_counter.most_common(5):
        print(f"  IP {ip}: {count} paketa")

    print("\nPortovi sa najviše aktivnosti:")
    for port, count in port_counter.most_common(5):
        print(f"  Port {port}: {count} paketa")

def main():
    """
    Glavna funkcija koja pokreće hvatanje mrežnog saobraćaja.
    """
    print("[INFO] Pokrećem analizu mrežnog saobraćaja...")
    try:
        
        sniff(filter="ip", prn=packet_handler, timeout=30)  
    except KeyboardInterrupt:
        print("\n[INFO] Sniffing prekinut ručno.")
    except Exception as e:
        print(f"[ERROR] Greška prilikom sniffinga: {e}")
    finally:
        display_summary()

if __name__ == "__main__":
    print("[INFO] Python analiza mrežnog saobraćaja")
    print(f"[INFO] Početak: {datetime.now()}")
    main()
    print(f"[INFO] Kraj: {datetime.now()}")
