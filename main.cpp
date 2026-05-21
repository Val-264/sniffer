#include "estructuras.h"

/*
* @brief             Procesa los pquetes capturados 
* @param user        Último argumento pasado a pcap_loop
* @param pkthdr      Puntero a la estructura Packet Header (pcap_pkthdr), apunta a la marca de tiempo y longitudes del paquete
* @param packetd_ptr Puntero a los daots del paquete 
*/
void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packetd_ptr) {
  Datos_Paquete record;
  record.id = id_paquete++;              // Asiganr ID del paquete 
  record.longitud_paquete = pkthdr->len; // Obtener longitud del paquete 

  // pkthdr->caplen Bytes capturados realmente 
  record.raw_data = vector<unsigned char>(packetd_ptr, packetd_ptr + pkthdr->caplen);

  eth_header *eth_hdr = (struct eth_header *)packetd_ptr;
  unsigned short eth_type = ntohs(eth_hdr->eth_type);

  const u_char *puntero_de_red = packetd_ptr + longitud_encabezado_de_red;
  const u_char *puntero_a_transporte = nullptr;
  unsigned char tipo_de_protocolo = 0;

  // Capas de enlace y de red 
  if (eth_type == 0x0806) { // Protococlo de resolución de direcciones (ARP)
    record.protocol = "ARP";
    record.src_ip = "MAC: " + to_string(eth_hdr->src_mac[0]);
    record.dest_ip = "MAC: " + to_string(eth_hdr->dest_mac[0]);
    paquetes_capturados.push_back(record);
  } 
  else if (eth_type == 0x0800) { // Protocolo de internet versión 4
    ip_header *ip_hdr = (struct ip_header *)puntero_de_red;

    char packet_scrip[INET_ADDRSTRLEN];
    char packet_dstip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), packet_scrip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), packet_dstip, INET_ADDRSTRLEN);

    record.src_ip = packet_scrip;
    record.dest_ip = packet_dstip;

    int packet_hlen = (ip_hdr->ip_vhl & 0x0F) * 4;
    puntero_a_transporte = puntero_de_red + packet_hlen;
    tipo_de_protocolo = ip_hdr->ip_p;
  }
  else if (eth_type == 0x08DD) {
    ipv6_header *ipv6_hdr = (struct ipv6_header *)puntero_de_red;

    char packet_scrip[INET6_ADDRSTRLEN];
    char packet_dstip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ipv6_hdr->ip_src), packet_scrip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6_hdr->ip_dst), packet_dstip, INET6_ADDRSTRLEN);

    record.src_ip = packet_scrip;
    record.dest_ip = packet_dstip;

    puntero_a_transporte = puntero_de_red + 40;
    tipo_de_protocolo = ipv6_hdr->next_header; 
  }
  else {
    stringstream ss;
    ss << "Capa 2 Desconocida (0x" << hex << eth_type << dec << ")";
    record.protocol = ss.str();
    paquetes_capturados.push_back(record);
    return;
  }
    
  // Capas de transporte y aplicación 
  if (puntero_a_transporte != nullptr) {
    tcp_header *tcp_hdr;
    udp_header *udp_hdr;
    icmp_header *icmp_hdr;

    switch (tipo_de_protocolo) {
      case IPPROTO_TCP:
        tcp_hdr = (struct tcp_header *)puntero_a_transporte;
        record.src_port = ntohs(tcp_hdr->th_sport);
        record.dest_port = ntohs(tcp_hdr->th_dport); 

        if (record.src_port == 21 || record.dest_port == 21) record.protocol = "FTP";
        else if (record.src_port == 22 || record.dest_port == 22) record.protocol = "SSH";
        else if (record.src_port == 23 || record.dest_port == 23) record.protocol = "Telnet";
        else if (record.src_port == 80 || record.dest_port == 80) record.protocol = "HTTP";
        else if (record.src_port == 443 || record.dest_port == 443) record.protocol = "HTTPS";
        else record.protocol = "TCP";
        break;

      case IPPROTO_UDP:
        udp_hdr = (struct udp_header *) puntero_a_transporte;
        record.src_port = ntohs(udp_hdr->uh_sport);
        record.dest_port = ntohs(udp_hdr->uh_dport);

        if (record.src_port == 53 || record.dest_port == 53) record.protocol = "DNS";
        else if (record.src_port == 67 || record.dest_port == 67 || 
                record.src_port == 68 || record.dest_port == 68) record.protocol = "DHCP";
        else record.protocol = "UDP";
        break;

      case IPPROTO_ICMP:
          icmp_hdr = (struct icmp_header *)puntero_a_transporte;
          record.protocol = "ICMPv4";
          record.extra_info = "Type: " + to_string(icmp_hdr->icmp_type); 
          break;

      case 58:
          icmp_hdr = (struct icmp_header *)puntero_a_transporte;
          record.protocol = "ICMPv6";
          record.extra_info = "Type: " + to_string(icmp_hdr->icmp_type); 
          break;
      default:
          record.protocol = "Protocolo IP: " + to_string(tipo_de_protocolo);
    }
  }

  paquetes_capturados.push_back(record);

  int col = 20;

  cout << "[" << record.id << "] " << setw(col) << record.protocol << setw(col)
              << record.src_ip <<  setw(col) << record.src_port << setw(col)  
              << record.dest_ip << setw(col)  << record.dest_port << setw(col)  << record.longitud_paquete << "\n";

}

void captura_de_paquetes() {
 if (pcap_loop(capdev, 0, call_me, (u_char *)NULL) < 0) {
        cerr << "ERR: pcap_loop() fallo: " << pcap_geterr(capdev) << "\n";
    }
}

int main(int argc, char const *argv[]) {
    // Inicializar Winsock (Esencial en Windows)
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "ERR: WSAStartup fallo.\n";
        return 1;
    }

    char error_buffer[PCAP_ERRBUF_SIZE];
    int packets_count = 30; // Capturaremos 10 paquetes para la prueba inicial
    
    pcap_if_t *alldevs;
    pcap_if_t *device;

// Buscar dispositivos de red activos
    if (pcap_findalldevs(&alldevs, error_buffer) == -1) {
        cerr << "ERR: pcap_findalldevs() " << error_buffer << "\n";
        WSACleanup();
        return 1;
    }

    if (alldevs == nullptr) {
        cerr << "No se encontraron interfaces. ¿Ejecutaste como Administrador?\n";
        WSACleanup();
        return 1;
    }

    // Menú de selección de interfaz 
    int i = 0;
    pcap_if_t *d;
    cout << "=== INTERFACES DISPONIBLES ===\n";
    for (d = alldevs; d != nullptr; d = d->next) {
        cout << ++i << ". " << d->name << "\n";
        if (d->description) {
            cout << "   Descripcion: " << d->description << "\n";
        } else {
            cout << "   Descripcion: No disponible\n";
        }
    }

    if (i == 0) {
        cout << "No se encontraron interfaces validas.\n";
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    int opcion;
    cout << "\nSelecciona el numero de interfaz activa (ej. la que diga Wireshark, Intel, Realtek o Wi-Fi): ";
    cin >> opcion;

    if (opcion < 1 || opcion > i) {
        cout << "Opcion invalida.\n";
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    // Avanzar en la lista hasta la opción elegida
    device = alldevs;
    for (int j = 1; j < opcion; j++) {
        device = device->next;
    }

    cout << "\nAbriendo interfaz: " << (device->description ? device->description : device->name) << "\n";


    // Abrir sesión de captura 
    capdev = pcap_open_live(device->name, BUFSIZ, 1, 1000, error_buffer);
    
    if (capdev == NULL) {
        cerr << "ERR: pcap_open_live() " << error_buffer << "\n";
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    // Liberar la lista de interfaces devueltas
    pcap_freealldevs(alldevs);

    // Configurar longitud de capa de enlace
    int link_hdr_type = pcap_datalink(capdev);
    switch (link_hdr_type) {
        case DLT_NULL:     longitud_encabezado_de_red = 4;  break;
        case DLT_EN10MB:   longitud_encabezado_de_red= 14; break;
        default:           longitud_encabezado_de_red = 0;
    }

    // Filtros BPF 
    struct bpf_program bpf;
    const char *filters = "";  // Se deja vacío para que catura ccualquier paquete 

    if (pcap_compile(capdev, &bpf, filters, 0, 0) == PCAP_ERROR) {
        cerr << "ERR: pcap_compile() " << pcap_geterr(capdev) << "\n";
    } else {
        if (pcap_setfilter(capdev, &bpf) == PCAP_ERROR) {
            cerr << "ERR: pcap_setfilter() " << pcap_geterr(capdev) << "\n";
        }
    }

    // Iniciar de multihilo y escucha
    cout << "\n--- ESCUCHANDO RED --- Envie trafico (abra el navegador o haga un ping)...\n\n";
    cout << "Presiona Enter si quieres detener al captura";

    int col =20;
    cout << "ID" << setw(col) << "PROTOCOLO" << setw(col) << "IP ORIGEN" << setw(col) 
    << "PUERTO DE ORIGEN " << setw(col) << "IP DESTINO" << setw(col) << "PUERTO DESTINO"
    << setw(col) << "LONGITUD PAQUETE\n";
   
    capturando = true;

    // Iniciar hilo para la captura de paquetes 
    thread hilo_de_captura(captura_de_paquetes);
    
    cin.ignore(); // Limpiar buffer 
    cin.get();    // Esperar a capturar Enter 

    // Si el se presiona Enter 
    if (capturando) {
        cout << "\nFin de la captura de paquetes";

        pcap_breakloop(capdev); // Función de npcap para detener la captura

        // Esperar a que el hilo de captura termine 
        if (hilo_de_captura.joinable()) {
            hilo_de_captura.join(); // Unir el hilo de captura con el hilo principal 
        }

        capturando = false;
    }

    // Verificación final del almacenamiento en memoria
    cout << "\n========================================================================\n";
    cout << "PROCESO COMPLETADO EXCEPCIONALMENTE.\n";
    cout << "Paquetes almacenados de forma segura en memoria (vector): " << paquetes_capturados.size() << "\n";
    cout << "========================================================================\n";

    pcap_close(capdev);
    WSACleanup();      // Terminar el uso de ws2tcpip.h
    return 0;
}