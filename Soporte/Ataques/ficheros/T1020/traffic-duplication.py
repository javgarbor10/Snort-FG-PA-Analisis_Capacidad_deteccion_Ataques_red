from scapy.all import *

# Interfaz de red que escuchará los paquetes
LISTEN_INTERFACE = "Ethernet 8"

def packet_callback(packet):
    # Reenviar el paquete al equipo A
    sendp(packet,iface="Ethernet 9", verbose=False)

def main():
    print(f"Escuchando en {LISTEN_INTERFACE} y reenviando paquetes...")
    sniff(iface=LISTEN_INTERFACE, prn=packet_callback)

if __name__ == "__main__":
    main()
