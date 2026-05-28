#include "estructuras.h"

static bool vista_analisis = false; // Bandera para controlar lo que se analiza en pantalla 

void dibujarInterfaz() {
    // Dimensiones inciales de la ventana 
    ImGui::SetNextWindowSize(ImVec2(1000, 700), ImGuiCond_FirstUseEver);
    ImGui::Begin("Sniffer de Red", nullptr, ImGuiWindowFlags_NoCollapse);

    if (!vista_analisis) {
        // =====================================================================
        // PANTALLA 1: SELECCIÓN DE INTERFAZ 
        // =====================================================================
        ImGui::Text("Bienvenido al Analizador de Trafico");
        ImGui::Separator();
        ImGui::Spacing();

        static int interfaz_seleccionada = 0;
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
    else {
        // =====================================================================
        // PANTALLA 2: ANÁLISIS DE TRÁFICO
        // =====================================================================

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

            // 2. Recorrer tu vector global para dibujar cada paquete capturado
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
                    // NOTA: Si 'protocolo' es un string, usamos .c_str() para ImGui
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

        ImGui::SameLine(); // Poner el Área 3 justo al lado del Área 2

        // --- ÁREA 3: CONTENIDO RAW (Hexadecimal) ---
        // Toma el ancho y altura restantes
        ImGui::BeginChild("Area3", ImVec2(0, 0), true);
        ImGui::Text("AREA 3: CONTENIDO RAW DEL PAQUETE");
        ImGui::EndChild();
    }

    ImGui::End();
}