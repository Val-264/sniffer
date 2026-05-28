#include "estructuras.h"
// Inicializar variables globales 
// Almacenamiento global de paquetes capturados
vector<Datos_Paquete> paquetes_capturados;
int id_paquete = 1;
int longitud_encabezado_de_red = 0;  // Longitud de los datos de la capa de enlace 
vector<InterfacesDeRed> lista_interfaces_de_red;

pcap_t* capdev = nullptr;
mutex mutex_paquetes; // Mutex para proteger el acceso al vector de paquetes en un entorno multihilo
atomic<bool> capturando(false);
thread hilo_de_captura;


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

  // Captuar el tiempo de llegada del paquete (marca de tiempo)
  time_t segundos_totales = pkthdr->ts.tv_sec; 
  tm info_tiempo;
  localtime_s(&info_tiempo, &segundos_totales); // Convertir a estructura tm

  char buffer_tiempo[64];

  // Mes, día, año , horas, minutos, segundos
  strftime(buffer_tiempo, sizeof(buffer_tiempo), "%m %d, %Y  %H:%M:%S.", &info_tiempo);
  record.tiempo_llegada = buffer_tiempo + to_string(pkthdr->ts.tv_sec);

  eth_header *eth_hdr = (struct eth_header *)packetd_ptr;
  unsigned short eth_type = ntohs(eth_hdr->eth_type);

  const u_char *puntero_de_red = packetd_ptr + longitud_encabezado_de_red;
  const u_char *puntero_a_transporte = nullptr;
  unsigned char tipo_de_protocolo = 0;

  // Capas de enlace y de red 
  if (eth_type == 0x0806) { // Protococlo de resolución de direcciones (ARP)
    record.protocolo = "ARP";
    record.src_ip = "MAC: " + to_string(eth_hdr->src_mac[0]);
    record.dest_ip = "MAC: " + to_string(eth_hdr->dest_mac[0]);
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
    record.protocolo = ss.str();
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

        if (record.src_port == 21 || record.dest_port == 21) record.protocolo = "FTP";
        else if (record.src_port == 22 || record.dest_port == 22) record.protocolo = "SSH";
        else if (record.src_port == 23 || record.dest_port == 23) record.protocolo = "Telnet";
        else if (record.src_port == 80 || record.dest_port == 80) record.protocolo = "HTTP";
        else if (record.src_port == 443 || record.dest_port == 443) record.protocolo = "HTTPS";
        else record.protocolo = "TCP";
        break;

      case IPPROTO_UDP:
        udp_hdr = (struct udp_header *) puntero_a_transporte;
        record.src_port = ntohs(udp_hdr->uh_sport);
        record.dest_port = ntohs(udp_hdr->uh_dport);

        if (record.src_port == 53 || record.dest_port == 53) record.protocolo = "DNS";
        else if (record.src_port == 67 || record.dest_port == 67 || 
                record.src_port == 68 || record.dest_port == 68) record.protocolo = "DHCP";
        else record.protocolo = "UDP";
        break;

      case IPPROTO_ICMP:
          icmp_hdr = (struct icmp_header *)puntero_a_transporte;
          record.protocolo = "ICMPv4";
          record.extra_info = "Type: " + to_string(icmp_hdr->icmp_type); 
          break;

      case 58:
          icmp_hdr = (struct icmp_header *)puntero_a_transporte;
          record.protocolo = "ICMPv6";
          record.extra_info = "Type: " + to_string(icmp_hdr->icmp_type); 
          break;
      default:
          record.protocolo = "Protocolo IP: " + to_string(tipo_de_protocolo);
    }
  }

  {
	  lock_guard<mutex> lock(mutex_paquetes);
      paquetes_capturados.push_back(record);
  }

  int col = 20;

  cout << "[" << record.id << "] " << setw(col) << record.protocolo << setw(col)
              << record.src_ip <<  setw(col) << record.src_port << setw(col)  
              << record.dest_ip << setw(col)  << record.dest_port << setw(col)  << record.longitud_paquete << "\n";

}

void captura_de_paquetes() {
 if (pcap_loop(capdev, 0, call_me, (u_char *)NULL) < 0) {
        cerr << "ERR: pcap_loop() fallo: " << pcap_geterr(capdev) << "\n";
    }
}

string filtrar() {
    string filtro;

    cout << "Filtro: ";
    cin.ignore();
    getline(cin, filtro);

    return filtro;
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
        InterfacesDeRed nuevaInterfaz;
		nuevaInterfaz.nombre_tecnico = d->name;
        if (d->description) {
			nuevaInterfaz.descripcion = d->description;
        } else {
            nuevaInterfaz.nombre_tecnico = d->name;
        }
		lista_interfaces_de_red.push_back(nuevaInterfaz);
    }

	pcap_freealldevs(alldevs); // Liberar memoria de la lista de interfaces

    if (lista_interfaces_de_red.empty()) {
        cout << "No se encontraron interfaces validas.\n";
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

	// Inicializar entorno de la interfaz gráfica (ImGui)
	if (!glfwInit()) {
		cerr << "ERR: No se pudo inicializar GLFW.\n";
		pcap_freealldevs(alldevs);
		WSACleanup();
		return 1;
	}

	GLFWwindow* ventana = glfwCreateWindow(800, 600, "Sniffer de red", NULL, NULL);
    if (!ventana) {
		cerr << "Error al abir la ventana de GLFW.\n";
		glfwTerminate();
        WSACleanup();
        return 1;
    }

    glfwMakeContextCurrent(ventana);
    glfwSwapInterval(1); // Activar V-Sync

    // Inicializar Dear ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForOpenGL(ventana, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    // Bucle de la interfaz gráfica 
    while (!glfwWindowShouldClose(ventana)) {
        // Captura de eventos como movimiento del mouse, click
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        dibujarInterfaz();

        // Renderizado 
        ImGui::Render();
        int ancho_ventana, alto_ventana;

        glfwGetFramebufferSize(ventana, &ancho_ventana, &alto_ventana);
        glViewport(0, 0, ancho_ventana, alto_ventana);
        glClearColor(0.1f, 0.15f, 0.2f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(ventana);

    }


    WSACleanup();      // Terminar el uso de ws2tcpip.h*/

	// Cierre seguro y liempeza de recursos
    if (capturando) {
        capturando = false;
        pcap_breakloop(capdev);
        if (hilo_de_captura.joinable()) {
            hilo_de_captura.join();
        }
    }

    if (capdev != nullptr) {
        pcap_close(capdev);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(ventana);
    glfwTerminate();
    WSACleanup();
    return 0; 
}