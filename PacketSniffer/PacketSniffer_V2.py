import scapy.all as scapy

# Función principal para capturar paquetes
def sniffing(interface, filter=None):
    print(f"[+] Iniciando captura en la interfaz {interface}...")
    try:
        scapy.sniff(
            iface=interface, 
            store=False,  # No almacenar paquetes en memoria
            filter=filter,  # Filtro opcional (BPF)
            prn=process_packet  # Función de callback para procesar cada paquete
        )
    except Exception as e:
        print(f"[-] Error durante la captura: {e}")

# Función para procesar cada paquete capturado
def process_packet(packet):
    # Capa IP
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src  # Dirección IP de origen
        ip_dst = packet[scapy.IP].dst  # Dirección IP de destino
        print(f"[+] IP Origen: {ip_src} -> IP Destino: {ip_dst}")

        # Verificar fragmentación
        if packet[scapy.IP].flags == "MF":  # More Fragments flag
            print("    [!] Este paquete está fragmentado.")

    # Capa TCP
    if packet.haslayer(scapy.TCP):
        tcp_sport = packet[scapy.TCP].sport  # Puerto de origen
        tcp_dport = packet[scapy.TCP].dport  # Puerto de destino
        flags = packet[scapy.TCP].flags  # Banderas TCP
        print(f"    [TCP] Puerto Origen: {tcp_sport} -> Puerto Destino: {tcp_dport}")

        # Detectar escaneos de puertos (SYN flag)
        if flags == "S":
            print(f"    [!] Posible escaneo de puertos detectado desde {packet[scapy.IP].src}")

        # Detectar tráfico cifrado (HTTPS)
        if tcp_dport == 443 or tcp_sport == 443:  # Puerto HTTPS
            print("    [!] Tráfico cifrado detectado (HTTPS).")

    # Capa UDP
    elif packet.haslayer(scapy.UDP):
        udp_sport = packet[scapy.UDP].sport  # Puerto de origen
        udp_dport = packet[scapy.UDP].dport  # Puerto de destino
        print(f"    [UDP] Puerto Origen: {udp_sport} -> Puerto Destino: {udp_dport}")

    # Capa ICMP
    elif packet.haslayer(scapy.ICMP):
        icmp_type = packet[scapy.ICMP].type  # Tipo de mensaje ICMP
        print(f"    [ICMP] Tipo: {icmp_type}")

    # Capa ARP
    elif packet.haslayer(scapy.ARP):
        arp_op = packet[scapy.ARP].op  # Operación ARP
        if arp_op == 1:
            print("    [ARP] Solicitud de resolución de dirección.")
        elif arp_op == 2:
            print("    [ARP] Respuesta de resolución de dirección.")

    # Datos de la capa de aplicación
    if packet.haslayer(scapy.Raw):
        try:
            data = packet[scapy.Raw].load.decode(errors='ignore')  # Decodificar datos
            print(f"    [Datos] Contenido: {data}")
        except Exception as e:
            print(f"    [Datos] Error al decodificar datos: {e}")

# Interfaz interactiva para el usuario
if __name__ == "__main__":
    print("=== Packet Sniffer ===")
    interface = input("Introduce la interfaz de red (ej. 'Wi-Fi', 'Ethernet', 'wlan0mon'): ")
    filter_input = input("Introduce un filtro BPF (opcional, ej. 'tcp port 80'): ")

    # Iniciar la captura
    sniffing(interface, filter=filter_input)