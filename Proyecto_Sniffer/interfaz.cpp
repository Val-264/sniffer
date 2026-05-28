#include "estructuras.h"

static bool vista_analisis = false; // Bandera para controlar lo que se analiza en pantalla 
static int interfaz_seleccionada = 0;


// =======================================================================================================================================
//                                                      PANTALLA 1: SELECCIÓN DE INTERFAZ 
// =======================================================================================================================================
// @brief Dibuja la pantalla de selección de interfaz, permitiendo al usuario elegir una interfaz de red para iniciar la captura de paquetes
void pantalla_interfaz() {
    ImGui::Text("Bienvenido al Analizador de Trafico");
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::Text("Seleccionar la interfaz de red para comenzar:");
    ImGui::SetNextItemWidth(500);

    if (!lista_interfaces_de_red.empty()) {
        string preview_actual = lista_interfaces_de_red[interfaz_seleccionada].descripcion;
        if (ImGui::BeginCombo("##combo_interfaces", preview_actual.c_str())) {
            for (int i = 0; i < lista_interfaces_de_red.size(); i++) {
                bool esta_seleccionado = (interfaz_seleccionada == i);
                if (ImGui::Selectable(lista_interfaces_de_red[i].descripcion.c_str(), esta_seleccionado)) {
                    interfaz_seleccionada = i;
                }
                if (esta_seleccionado) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }

        ImGui::Spacing();

        // Cambiar de pantalla a análisis de tráfico al iniciar la captura
        if (ImGui::Button("Iniciar Captura", ImVec2(150, 30))) {
            char error_buffer[PCAP_ERRBUF_SIZE];
            string device_name = lista_interfaces_de_red[interfaz_seleccionada].nombre_tecnico;

            capdev = pcap_open_live(device_name.c_str(), BUFSIZ, 1, 1000, error_buffer);
            if (capdev != nullptr) {
                int link_hdr_type = pcap_datalink(capdev);
                longitud_encabezado_de_red = (link_hdr_type == DLT_NULL) ? 4 : (link_hdr_type == DLT_EN10MB) ? 14 : 0;

                struct bpf_program bpf;
                if (pcap_compile(capdev, &bpf, "", 0, 0) != PCAP_ERROR) {
                    pcap_setfilter(capdev, &bpf);
                }

                capturando = true;
                vista_analisis = true; // Cambiar la vista a análisis de tráfico
                hilo_de_captura = thread(captura_de_paquetes);
            }
        }
    }
    else {
        ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "No se encontraron interfaces activas.");
    }
}
// =======================================================================================================================================
//                                                      PANTALLA 2: ANÁLISIS DE TRÁFICO
// =======================================================================================================================================
// @brief Dibuja la pantalla de análisis de tráfico, mostrando la lista de paquetes capturados y detalles del paquete seleccionado
void pantalla_analisis() {
    // --- BARRA DE HERRAMIENTAS SUPERIOR ---
    if (ImGui::Button("Detener")) {
        if (capturando) {
            capturando = false;
            if (capdev != nullptr) pcap_breakloop(capdev);
            if (hilo_de_captura.joinable()) hilo_de_captura.join();
            if (capdev != nullptr) { pcap_close(capdev); capdev = nullptr; }
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Volver a Interfaces")) {
        // Ocultamor vista de análisis y volver al menu de interfaces 
        if (capturando) {
            // Forzamos detener si aÚn está capturando
            capturando = false;
            if (capdev != nullptr) pcap_breakloop(capdev);
            if (hilo_de_captura.joinable()) hilo_de_captura.join();
            if (capdev != nullptr) { pcap_close(capdev); capdev = nullptr; }
        }
        {
            lock_guard<mutex> lock(mutex_paquetes); // Aseguramos que no haya acceso concurrente a la lista de paquetes
            paquetes_capturados.clear();
            id_paquete = 0;
        }



        vista_analisis = false;
    }
    ImGui::SameLine();
    ImGui::Text(" | Filtro:"); ImGui::SameLine();
    static char filtro_texto[128] = "";
    ImGui::InputText("##Filtro", filtro_texto, IM_ARRAYSIZE(filtro_texto));

    ImGui::Separator();

    // Calculamos el espacio disponible
    float ancho_total = ImGui::GetContentRegionAvail().x;
    float alto_total = ImGui::GetContentRegionAvail().y;

    // --- ÁREA 1: TRÁFICO CAPTURADO (Lista de Paquetes) ---
    ImGui::BeginChild("Area1", ImVec2(ancho_total, alto_total * 0.55f), true);

    // Variable para recordar qué paquete (fila) seleccionó el usuario
    static int indice_paquete_seleccionado = -1;

    // Configurar el diseño  de la tabla
    static ImGuiTableFlags banderas_tabla =
        ImGuiTableFlags_Borders |
        ImGuiTableFlags_RowBg |
        ImGuiTableFlags_Resizable |
        ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_HighlightHoveredColumn;

    if (ImGui::BeginTable("TablaPaquetes", 6, banderas_tabla)) {
        // 1. Configurar los títulos y anchos de las columnas
        ImGui::TableSetupColumn("No.", ImGuiTableColumnFlags_WidthFixed, 40.0f);
        ImGui::TableSetupColumn("Protocolo", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Origen");
        ImGui::TableSetupColumn("Destino");
        ImGui::TableSetupColumn("Puertos(src->dest)");
        ImGui::TableSetupColumn("Longitud", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableHeadersRow();

        // Recorrer el  vector global para dibujar cada paquete capturado
        {
            lock_guard<mutex> lock(mutex_paquetes); // Aseguramos que no haya acceso concurrente a la lista de paquetes

            for (int i = 0; i < paquetes_capturados.size(); i++) {
                ImGui::TableNextRow();

                // Verificamos si esta es la fila a la que el usuario le dio clic
                bool esta_seleccionado = (indice_paquete_seleccionado == i);

                // Columna 0: Número de ID (Aquí hacemos que toda la fila sea clickeable)
                ImGui::TableSetColumnIndex(0);
                string id_str = to_string(paquetes_capturados[i].id);
                if (ImGui::Selectable(id_str.c_str(), esta_seleccionado, ImGuiSelectableFlags_SpanAllColumns)) {
                    indice_paquete_seleccionado = i; // Guardamos el índice si hacen clic
                }

                // Columna 1: Protocolo
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%s", paquetes_capturados[i].protocolo.c_str());

                // Columna 2: IP Origen
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%s", paquetes_capturados[i].src_ip.c_str());

                // Columna 3: IP Destino
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%s", paquetes_capturados[i].dest_ip.c_str());

                // Columna 4: Puertos (Origen -> Destino)
                ImGui::TableSetColumnIndex(4);
                string puertos = to_string(paquetes_capturados[i].src_port) +
                    " -> " + to_string(paquetes_capturados[i].dest_port);
                ImGui::Text("%s", puertos.c_str());

                // Columna 5: Longitud
                ImGui::TableSetColumnIndex(5);
                ImGui::Text("%d", paquetes_capturados[i].longitud_paquete);
            }
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    // Hacer una copia segura del paquete seleccionado para no mantener el candado cerrado mucho tiempo
    bool hay_seleccion = false;
    Datos_Paquete paquete_actual;

    {
        lock_guard<mutex> lock(mutex_paquetes);
        if (indice_paquete_seleccionado >= 0 && indice_paquete_seleccionado < paquetes_capturados.size()) {
            paquete_actual = paquetes_capturados[indice_paquete_seleccionado];
            hay_seleccion = true;
        }
    }

    // --- ÁREA 2: INFORMACIÓN ESTRUCTURADA ---
    ImGui::BeginChild("Area2", ImVec2(ancho_total * 0.5f, 0), true);
    ImGui::TextUnformatted("AREA 2: INFORMACION ESTRUCTURADA");
    ImGui::Separator();

    if (hay_seleccion) {
        // Armar el primer nodo con la información general del paquete
        int tam_bits_cable = paquete_actual.longitud_paquete * 8;
        string titulo_frame = "Frame " + to_string(paquete_actual.id) +
            ": " + to_string(paquete_actual.longitud_paquete) +
            " bytes en cable" + " (" + to_string(tam_bits_cable) + " bits)";

        if (ImGui::TreeNode(titulo_frame.c_str())) {
            int tam_bits_capturado = paquete_actual.raw_data.size() * 8;
            string texto_longitud = "Longitud de captura: " + to_string(paquete_actual.raw_data.size()) + " bytes"
                + " (" + to_string(tam_bits_capturado) + " bits)";
            string nombre_interfaz = lista_interfaces_de_red[interfaz_seleccionada].nombre_tecnico;
            string desc_interfaz = lista_interfaces_de_red[interfaz_seleccionada].descripcion;
            string texto_interfaz = "ID de la interfaz: 0 (" + nombre_interfaz;
            string tiempo_llegada = "Hora de llegada: "; // @TODO Agregar marca de tiempo real del paquete con pcap_pkthdr->ts
            string texto_no_paquete = "No. paquete: " + to_string(indice_paquete_seleccionado + 1);
            string texto_longitud_paquete = "Longitud paquete: " + to_string(paquete_actual.longitud_paquete) + "bytes ("
                + to_string(tam_bits_cable) + " bits)";
            string texto_longitud_capturada = "Longitud capturada: " + to_string(paquete_actual.raw_data.size()) + "bytes ("
                + to_string(tam_bits_capturado) + " bits)";

            ImGui::TextUnformatted(texto_longitud.c_str());
            if (ImGui::TreeNode(texto_interfaz.c_str())) {
                string txt_nombre = "Nombre de la interfaz: " + nombre_interfaz;
                string txt_desc = "Descripción de la interfaz: " + desc_interfaz;
                ImGui::TextUnformatted(txt_nombre.c_str());
                ImGui::TextUnformatted(txt_desc.c_str());
                ImGui::TreePop();
            }
            ImGui::TextUnformatted(tiempo_llegada.c_str());
            ImGui::TextUnformatted(texto_no_paquete.c_str());
            ImGui::TextUnformatted(texto_longitud_paquete.c_str());
            ImGui::TextUnformatted(texto_longitud_capturada.c_str());
            ImGui::TreePop();
        }
        
        //Armar nodo de Ethernet II
		string titulo_ethernet = "Ethernet II, Origen: " + paquete_actual.src_ip 
            + " Destino: " + paquete_actual.dest_ip;
        if (ImGui::TreeNode(titulo_ethernet.c_str())) {
			string txt_dst = "Destino: " + paquete_actual.dest_ip;
			string txt_src = "Origen: " + paquete_actual.src_ip;

			ImGui::TextUnformatted(txt_dst.c_str());
			ImGui::TextUnformatted(txt_src.c_str());

            // Tipo 
            if (paquete_actual.protocolo == "ARP") {
                ImGui::TextUnformatted("Tipo: ARP (0x0806)");
            }
            else if (paquete_actual.protocolo == "IPv6" || paquete_actual.protocolo == "ICMPv6") {
                ImGui::TextUnformatted("Tipo: IPv6 (0x86DD)");
            }
            else {
                ImGui::TextUnformatted("Tipo: IPv4 (0x0800)");
            }

            ImGui::TreePop();
        }

        // Armar el nodo con la informacion del protcolo 
        string titulo_protocolo = "Protocolo: " + paquete_actual.protocolo;

        if (ImGui::TreeNode(titulo_protocolo.c_str())) {
            string txt_origen = "Origen: " + paquete_actual.src_ip;
            string txt_destino = "Destino: " + paquete_actual.dest_ip;
            string txt_puerto_o = "Puerto Origen: " + to_string(paquete_actual.src_port);
            string txt_puerto_d = "Puerto Destino: " + to_string(paquete_actual.dest_port);

            // Dibujamr el texto
            ImGui::TextUnformatted(txt_origen.c_str());
            ImGui::TextUnformatted(txt_destino.c_str());
            ImGui::TextUnformatted(txt_puerto_o.c_str());
            ImGui::TextUnformatted(txt_puerto_d.c_str());

            if (!paquete_actual.extra_info.empty()) {
                string txt_extra = "Info Adicional: " + paquete_actual.extra_info;
                ImGui::TextUnformatted(txt_extra.c_str());
            }
            ImGui::TreePop();
        }

        // Armar nodo específico para protocolo ARP 
        if (paquete_actual.protocolo == "ARP") {
            if (ImGui::TreeNode("Address Resolution Protocol (ARP)")) {
                ImGui::TextUnformatted("Hardware type: Ethernet (1)");
                ImGui::TextUnformatted("Protocol type: IPv4 (0x0800)");
                ImGui::TextUnformatted("Hardware size: 6");
                ImGui::TextUnformatted("Protocol size: 4");

                ImGui::TextUnformatted(("Sender MAC address: " + paquete_actual.src_ip).c_str());
                ImGui::TextUnformatted(("Target MAC address: " + paquete_actual.dest_ip).c_str());

                ImGui::TreePop();
            }
        }
    }
    else {
        ImGui::TextDisabled("Seleccione un paquete en la tabla superior...");
    }
    ImGui::EndChild();


    ImGui::SameLine(); // Poner el Área 3 justo al lado del Área 2

    // --- ÁREA 3: CONTENIDO RAW (Hexadecimal) ---
    // Toma el ancho y altura restantes
    ImGui::BeginChild("Area3", ImVec2(0, 0), true);
    ImGui::Text("AREA 3: CONTENIDO RAW DEL PAQUETE");
    ImGui::EndChild();
}


/*
* @brief Dibuja la interfaz gráfica utilizando ImGui. Controla dos vistas: selección de interfaz y análisis de tráfico.
*/
void dibujarInterfaz() {
    // Dimensiones inciales de la ventana 
    ImGui::SetNextWindowSize(ImVec2(1000, 700), ImGuiCond_FirstUseEver);
    ImGui::Begin("Sniffer de Red", nullptr, ImGuiWindowFlags_NoCollapse);

    if (!vista_analisis) {
		pantalla_interfaz();
    }
    else {
		pantalla_analisis();
    }

    ImGui::End();
}

