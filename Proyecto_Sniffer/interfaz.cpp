// Control de la interfaz gráfica 

#include "estructuras.h"

static bool vista_analisis = false; // Bandera para controlar lo que se analiza en pantalla 
static int interfaz_seleccionada = 0;
static bool filtro_activo = false; // Bandera para controlar si se ha aplicado un filtro de captura o no
static char filtro_antes_captura[256] = "";
static char filtro_captura[256] = "";
static string filtro_aplicado = "";
static bool coincide = true; // Mostrar todo el tráfico por defecto, pero si el usuario aplica un filtro, entonces solo mostrar los paquetes que coincidan con el filtro aplicado


// Banderas para controlar la exportación de tráfico a CSV
static bool contenido_por_default = false;
static bool contenido_personalizado = false;
static bool personalizar = false;
static bool contenido_filtrado = false;
static bool exportacion_seleccionada = false;
static bool exportacion_exitosa = false;

// Banderas para las checkboxes de contenido personalizado
static bool no_columna = false;
static bool protocolo_columna = false;
static bool origen_columna = false;
static bool destino_columna = false;
static bool puerto_origen_columna = false;
static bool puerto_destino_columna = false;
static bool longitud_columna = false;
static bool tiempo_local_columna = false;
static bool tiempo_utc_columna = false;
static bool tiempo_epoch_columna = false;


// *@brief Estilo aplicable a toda la interfaz 
void establecer_estilo_general() {
    ImGuiStyle& estilo_gral = ImGui::GetStyle();

    // Redondear botones 
    estilo_gral.FrameRounding = 5.0f;

	// Redondear ventanas emergentes 
    estilo_gral.ChildRounding = 5.0f;
    estilo_gral.PopupRounding = 5.0f;
}

// =======================================================================================================================================
//                                                      PANTALLA 1: SELECCIÓN DE INTERFAZ 
// =======================================================================================================================================
// @brief Dibuja la pantalla de selección de interfaz, permitiendo al usuario elegir una interfaz de red para iniciar la captura de paquetes
void mostrar_pantalla_interfaz() {

    ImGui::Text("Bienvenido al Analizador de Trafico\nSelecciona una interfaz para comenzar a capturar\n");
    ImGui::Separator();
    ImGui::Spacing();

    // Filtro de captura bpf opcional para que el usuario pueda escribir un filtro antes de iniciar la captura 
    ImGui::Text("Filtro (Puedes configurar un filtro antes de comenzar la captura):");
    ImGui::SetNextItemWidth(500);
    ImGui::InputText("##FiltroBPF", filtro_antes_captura, IM_ARRAYSIZE(filtro_antes_captura));
    ImGui::Spacing();

    ImGui::Text("Interfaces disponibles:");
    ImGui::SetNextItemWidth(500);

    if (!lista_interfaces_de_red.empty()) {
        string preview_actual = lista_interfaces_de_red[interfaz_seleccionada].descripcion;
        bool hay_seleccion = false;
        // Estandatizar el tamaño de los botones para que se vean uniformes
        ImVec2 tamanio_boton = ImVec2(450.0f, 30.0f);       
		// Alinear el texto de los botones hacia la izquierda y agregar padding para mejorar la apariencia
        ImGui::PushStyleVar(ImGuiStyleVar_ButtonTextAlign, ImVec2(0.0f, 0.5f));
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.0f, 6.0f));
        for (int i = 0; i < lista_interfaces_de_red.size(); i++) {
            if (ImGui::Button(lista_interfaces_de_red[i].descripcion.c_str(), tamanio_boton)) {
                interfaz_seleccionada = i;
                hay_seleccion = true;      
            }
            ImGui::Spacing();
        }

		ImGui::PopStyleVar(2); // ButtonTextAlign

        if (hay_seleccion) {
            char error_buffer[PCAP_ERRBUF_SIZE];
            string device_name = lista_interfaces_de_red[interfaz_seleccionada].nombre_tecnico;

            capdev = pcap_open_live(device_name.c_str(), BUFSIZ, 1, 1000, error_buffer);
            if (capdev != nullptr) {
                int link_hdr_type = pcap_datalink(capdev);
                longitud_encabezado_de_red = (link_hdr_type == DLT_NULL) ? 4 : (link_hdr_type == DLT_EN10MB) ? 14 : 0;

                struct bpf_program bpf;
                if (pcap_compile(capdev, &bpf, filtro_antes_captura, 0, 0) != PCAP_ERROR) {
                    pcap_setfilter(capdev, &bpf);
                }
                else {
                    cerr << "ERR: No se pudo compilar el filtro BPF: " << pcap_geterr(capdev) << "\n";
                }

                capturando = true;
                vista_analisis = true; // Cambiar la vista a análisis de tráfico
                hilo_de_captura = thread(captura_de_paquetes);
            }

        }

        ImGui::Spacing();

    }
    else {
        ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "No se encontraron interfaces activas.");
    }
}

// *@briefLimpiar banderas de exportacion para no afectar a la siguiente exportacion
void limpiar_banderas_exportacion() {
    contenido_por_default = false;
    contenido_personalizado = false;
    personalizar = false;
    contenido_filtrado = false;
    exportacion_seleccionada = false;
    exportacion_exitosa = false;
    no_columna = false;
    protocolo_columna = false;
    origen_columna = false;
    destino_columna = false;
    puerto_origen_columna = false;
    puerto_destino_columna = false;
    longitud_columna = false;
    tiempo_local_columna = false;
    tiempo_utc_columna = false;
    tiempo_epoch_columna = false;
}

/*
* @brief Aplica el filtro de captura escrito por el usuario en la interfaz gráfica, mostrando solo los paquetes que coincidan con el filtro aplicado
* @param i Índice del paquete en el vector global de paquetes capturados que se está evaluando para mostrar en la tabla de análisis de tráfico
*/
void filtrar_trafico(int i) {
    if (!filtro_aplicado.empty()) {
        coincide = false;

        // Copiamos el filtro y lo pasamos a minúsculas
        string filtro = filtro_aplicado;
        for (auto& c : filtro) c = tolower(c);

        string prot = paquetes_capturados[i].protocolo;
        for (auto& c : prot) c = tolower(c);

        string ip_src = paquetes_capturados[i].src_ip;
        string ip_dst = paquetes_capturados[i].dest_ip;
        string p_src = to_string(paquetes_capturados[i].src_port);
        string p_dst = to_string(paquetes_capturados[i].dest_port);

        size_t pos_eq = filtro.find("==");

        if (pos_eq != string::npos) {
            string clave = filtro.substr(0, pos_eq);
            string valor = filtro.substr(pos_eq + 2);

            clave.erase(0, clave.find_first_not_of(" \t"));
            clave.erase(clave.find_last_not_of(" \t") + 1);
            valor.erase(0, valor.find_first_not_of(" \t"));
            valor.erase(valor.find_last_not_of(" \t") + 1);

            if (clave == "ip.src" && ip_src.find(valor) != string::npos) coincide = true;
            else if (clave == "ip.dst" && ip_dst.find(valor) != string::npos) coincide = true;
            else if ((clave == "tcp.srcport" || clave == "udp.srcport") && p_src == valor) coincide = true;
            else if ((clave == "tcp.dstport" || clave == "udp.dstport") && p_dst == valor) coincide = true;
            else if ((clave == "tcp.port" || clave == "udp.port") && (p_src == valor || p_dst == valor)) coincide = true;
        }
        else {
            filtro.erase(0, filtro.find_first_not_of(" \t"));
            filtro.erase(filtro.find_last_not_of(" \t") + 1);

            // Si escriben solo el protocolo 
            if (prot == filtro) coincide = true;
        }
    }
}

// =======================================================================================================================================
//                                                      PANTALLA 2: ANÁLISIS DE TRÁFICO
// =======================================================================================================================================
// @brief Dibuja la pantalla de análisis de tráfico, mostrando la lista de paquetes capturados y detalles del paquete seleccionado
void mostrar_pantalla_analisis() {
    static bool exportar = false;
    // @TODO arreglar para que valide nombres
    // en blanco y nombres repetidos, poner archivos en una ruta específica 

    // --- BARRA DE HERRAMIENTAS SUPERIOR ---
    
    if (ImGui::Button("Volver a Interfaces")) {
        // Ocultar vista de análisis y volver al menu de interfaces 
        if (capturando) {
            exportar = false;
            // Forzamos detener si aún está capturando
            capturando = false;
            if (capdev != nullptr) pcap_breakloop(capdev);
            if (hilo_de_captura.joinable()) hilo_de_captura.join();
            if (capdev != nullptr) { pcap_close(capdev); capdev = nullptr; }
        }
        {
            lock_guard<mutex> lock(mutex_paquetes); // Asegurar que no haya acceso concurrente a la lista de paquetes
            paquetes_capturados.clear();
            id_paquete = 0;
        }

        vista_analisis = false;
    }

    ImGui::SameLine();
    if (ImGui::Button("Detener")) {
        if (capturando) {
            capturando = false;
            if (capdev != nullptr) pcap_breakloop(capdev);
            if (hilo_de_captura.joinable()) hilo_de_captura.join();
            if (capdev != nullptr) { pcap_close(capdev); capdev = nullptr; }
        }
    }


    ImGui::SameLine();
    if (ImGui::Button("Reiniciar captura")) {
        if (!capturando) {

        }
    }

    ImGui::SameLine();
    ImGui::Text(" | Filtro:"); ImGui::SameLine();
    ImGui::InputText("##Filtro", filtro_captura, IM_ARRAYSIZE(filtro_captura));

	if (!filtro_activo && strlen(filtro_captura) > 0) {
		filtro_activo = true;
	}
	else if (filtro_activo && strlen(filtro_captura) == 0) {
		filtro_activo = false;
	}

    ImGui::SameLine();
    static bool filtro_activo_en_captura = false;
    if (ImGui::Button("Quitar Filtro")) {
            filtro_captura[0] = '\0'; // Limpiar el filtro
            filtro_aplicado = "";
            filtro_activo_en_captura = false;
			coincide = true; // Mostrar todo el tráfico nuevamente
    }

    ImGui::SameLine();
    if (ImGui::Button("Aplicar Filtro")) {
        filtro_aplicado = string(filtro_captura);
        filtro_activo_en_captura = true;
    }    

    ImGui::Separator();
    static char nombre_archivo[256] = "";
    if (ImGui::Button("Exportar")) {
        if (!capturando) {
			exportar = true;
        }
    }

    if (exportar) { 

        // Contendio de la ventana emergente 
		if (!exportacion_seleccionada) {
            ImGui::OpenPopup("Configuracion de exportacion");
            if (ImGui::BeginPopupModal("Configuracion de exportacion", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {

                if (ImGui::Selectable(">> Contenido por default")) {
                    contenido_por_default = true;
                    contenido_personalizado = false;
                    contenido_filtrado = false;
                    exportacion_seleccionada = true;
                    ImGui::CloseCurrentPopup();
                }
                if (ImGui::Selectable(">> Contenido personalizado")) {
                    contenido_por_default = false;
                    contenido_personalizado = true;
                    contenido_filtrado = false;
                    exportacion_seleccionada = true;
                    personalizar = true;


                    ImGui::CloseCurrentPopup();
                }
                if (filtro_activo_en_captura) {
                    if (ImGui::Selectable(">> Solo lo filtrado\n   Contenido por default")) {
                        contenido_por_default = false;
                        contenido_personalizado = false;
                        contenido_filtrado = true;
                        exportacion_seleccionada = true;
                        ImGui::CloseCurrentPopup();
                    }
                }

                if (ImGui::Selectable(">> Cancelar")) {
					limpiar_banderas_exportacion(); // Limpiar banderas de exportación para no afectar a la próxima exportación
                    exportar = false;
                    ImGui::CloseCurrentPopup();
                }

                ImGui::EndPopup();
            }
		}

        if (personalizar) {
            ImGui::OpenPopup("Exportacion personalizada");
            if (ImGui::BeginPopupModal("Exportacion personalizada", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                ImGui::Checkbox("No.", &no_columna); ImGui::Spacing();
                ImGui::Checkbox("Protocolo", &protocolo_columna); ImGui::Spacing();
                ImGui::Checkbox("Origen (IP/MAC)", &origen_columna); ImGui::Spacing();
                ImGui::Checkbox("Destino (IP/MAC)", &destino_columna); ImGui::Spacing();
                ImGui::Checkbox("Puerto origen", &puerto_origen_columna);ImGui::Spacing();
                ImGui::Checkbox("Puerto destino", &puerto_destino_columna);
                ImGui::Checkbox("Longitud (Bytes)", &longitud_columna); ImGui::Spacing();
                ImGui::Checkbox("Tiempo Local", &tiempo_local_columna); ImGui::Spacing();
                ImGui::Checkbox("Tiempo UTC", &tiempo_utc_columna); ImGui::Spacing();
                ImGui::Checkbox("Tiempo Epoch", &tiempo_epoch_columna); ImGui::Separator();
                if (ImGui::Button("OK")) {
                    personalizar = false;
                    ImGui::CloseCurrentPopup();
                    
                }
                if (ImGui::Button("Cancelar")) {

					limpiar_banderas_exportacion(); // Limpiar banderas de exportación para no afectar a la próxima exportación
                    exportar = false;
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }
        }
       
		// Capturar nombre del archivo a exportar
        char extension_archivo[10] = ".csv";
        ImGui::SameLine();
        ImGui::Text(" | Nombre archivo: "); ImGui::SameLine();
        ImGui::InputText("##NombreArchivo", nombre_archivo, IM_ARRAYSIZE(nombre_archivo));
        ImGui::SameLine();


        if (ImGui::Button("Guardar CSV")) {
            strcat_s(nombre_archivo, extension_archivo);      // Añadir extensión al nombre ingresado por el usuario
            ofstream archivo(nombre_archivo);
            if (archivo.is_open()) {
                exportar = false; 

                if (contenido_por_default) {
                    // Escribir el encabezado del CSV 
                    archivo << "No.,Protocolo,Origen,Destino,Puerto Origen,Puerto Destino,Longitud (Bytes),Tiempo Local,Tiempo UTC,Tiempo Epoch\n";

                    // Bloquear el vector con el candado para leer los datos de forma segura
                    {
                        lock_guard<mutex> lock(mutex_paquetes);

                        for (const auto& pkt : paquetes_capturados) {
                            archivo << pkt.id << ","
                                << pkt.protocolo << ","
                                << pkt.src_ip << ","
                                << pkt.dest_ip << ","
                                << pkt.src_port << ","
                                << pkt.dest_port << ","
                                << pkt.longitud_paquete << ","
                                << pkt.tiempo_llegada << ","
                                << pkt.tiempo_llegada_utc << ","
                                << pkt.tiempo_epoch << "\n";
                        }
                    }

                }

				if (contenido_filtrado) {
					// Escribir el encabezado del CSV 
					archivo << "No.,Protocolo,Origen,Destino,Puerto Origen,Puerto Destino,Longitud (Bytes),Tiempo Local,Tiempo UTC,Tiempo Epoch\n";
					// Bloquear el vector con el candado para leer los datos de forma segura
					{
						lock_guard<mutex> lock(mutex_paquetes);
                        for (size_t i = 0; i < paquetes_capturados.size(); i++) {
							filtrar_trafico(i);
							if (coincide) {
								const auto& pkt = paquetes_capturados[i];
								archivo << pkt.id << ","
									<< pkt.protocolo << ","
									<< pkt.src_ip << ","
									<< pkt.dest_ip << ","
									<< pkt.src_port << ","
									<< pkt.dest_port << ","
									<< pkt.longitud_paquete << ","
									<< pkt.tiempo_llegada << ","
									<< pkt.tiempo_llegada_utc << ","
									<< pkt.tiempo_epoch << "\n";
							}
						}
					}
				}

                if (contenido_personalizado) {

                    // Formar encabezado de CVS dependiendo de la selección del usuario
                    if (no_columna) archivo << "No.,";
					if (protocolo_columna) archivo << "Protocolo,";
					if (origen_columna) archivo << "Origen,";
					if (destino_columna) archivo << "Destino,";
					if (puerto_origen_columna) archivo << "Puerto Origen,";
					if (puerto_destino_columna) archivo << "Puerto Destino,";
					if (longitud_columna) archivo << "Longitud (Bytes),";
					if (tiempo_local_columna) archivo << "Tiempo Local,";
					if (tiempo_utc_columna) archivo << "Tiempo UTC,";
					if (tiempo_epoch_columna) archivo << "Tiempo Epoch,";
					archivo << "\n";

                    {
                        lock_guard<mutex> lock(mutex_paquetes);
                        for (const auto& pkt : paquetes_capturados) {
                            filtrar_trafico(pkt.id - 1); // El ID del paquete es su posición en la lista + 1, entonces para obtener la posición correcta restamos 1
                            if (coincide) {
                                if (no_columna) archivo << pkt.id << ",";
                                if (protocolo_columna) archivo << pkt.protocolo << ",";
                                if (origen_columna) archivo << pkt.src_ip << ",";
                                if (destino_columna) archivo << pkt.dest_ip << ",";
                                if (puerto_origen_columna) archivo << pkt.src_port << ",";
                                if (puerto_destino_columna) archivo << pkt.dest_port << ",";
                                if (longitud_columna) archivo << pkt.longitud_paquete << ",";
                                if (tiempo_local_columna) archivo << pkt.tiempo_llegada << ",";
                                if (tiempo_utc_columna) archivo << pkt.tiempo_llegada_utc << ",";
                                if (tiempo_epoch_columna) archivo << pkt.tiempo_epoch;
                                archivo << "\n";
                            }
                        }
                        
                    }


                    
                }

                archivo.close();
				nombre_archivo[0] = '\0'; // Limpiar el nombre del archivo para la próxima exportación

				exportacion_exitosa = true;

                cout << "Exportacion exitosa archivo creado";
				
            }
            else {
                ImGui::OpenPopup("Fallo al exportar");
                if (ImGui::BeginPopupModal("Fallo al exportar", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                    ImGui::TextUnformatted("No se pudo crear el archivo CSV");
                    ImGui::Spacing();
                    if (ImGui::Button("OK", ImVec2(80.0f, 30.0f))) {
                        // Limpiar banderas de exportación para la próxima vez
						limpiar_banderas_exportacion();

                        ImGui::CloseCurrentPopup();
                    }
                    ImGui::EndPopup();
                }

                cerr << "ERR: No se pudo crear el archivo CSV.\n";
            }
        }
    }

    if (exportacion_exitosa) {
        ImGui::OpenPopup("Exportacion Exitosa");
        if (ImGui::BeginPopupModal("Exportacion Exitosa", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::TextUnformatted("Trafico exportado exitosamente al CSV");
            ImGui::Spacing();
            if (ImGui::Button("OK", ImVec2(80.0f, 30.0f))) {
				limpiar_banderas_exportacion(); // Limpiar banderas de exportación para la próxima vez
				exportacion_exitosa = false;

                ImGui::CloseCurrentPopup();              
            }
            ImGui::EndPopup();
        }


    }


    ImGui::Separator();

    // Calcular el espacio disponible
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
        // Configurar los títulos y anchos de las columnas
        ImGui::TableSetupColumn("No.", ImGuiTableColumnFlags_WidthFixed, 40.0f);
        ImGui::TableSetupColumn("Protocolo", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Origen");
        ImGui::TableSetupColumn("Destino");
        ImGui::TableSetupColumn("Puertos(src->dest)");
        ImGui::TableSetupColumn("Longitud", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableHeadersRow();

        bool scroll_fondo = (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() );

        // Recorrer el  vector global para dibujar cada paquete capturado
        {
            lock_guard<mutex> lock(mutex_paquetes); // Aseguramos que no haya acceso concurrente a la lista de paquetes

            for (int i = 0; i < paquetes_capturados.size(); i++) {
				filtrar_trafico(i); 
                // Si el paquete no cumple con el filtro, saltar a la siguiente iteración sin dibujarlo
                if (!coincide) continue;

                ImGui::TableNextRow();

				ImGui::PushID(i); // Usar el índice como ID para evitar conflictos en la tabla

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
                ImGui::TextUnformatted(paquetes_capturados[i].protocolo.c_str());

                // Columna 2: Origen
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(paquetes_capturados[i].src_ip.c_str());

                // Columna 3: Destino
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(paquetes_capturados[i].dest_ip.c_str());

                // Columna 4: Puertos (Origen -> Destino)
                ImGui::TableSetColumnIndex(4);
                string puertos = to_string(paquetes_capturados[i].src_port) +
                    " -> " + to_string(paquetes_capturados[i].dest_port);
                ImGui::TextUnformatted(puertos.c_str());

                // Columna 5: Longitud
                ImGui::TableSetColumnIndex(5);
				string long_paquete = to_string(paquetes_capturados[i].longitud_paquete) + " bytes";
                ImGui::TextUnformatted(long_paquete.c_str());

				ImGui::PopID();
            }
        }
        if (scroll_fondo) { ImGui::SetScrollHereY(1.0f); }
        
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
            string tiempo_llegada = "Hora de llegada: " + paquete_actual.tiempo_llegada; 
			string tiempo_llegada_utc = "Hora de llegada UTC: " + paquete_actual.tiempo_llegada_utc;
			string tiempo_epoch = "Tiempo de llegada Epoch: " + paquete_actual.tiempo_epoch;
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
			ImGui::TextUnformatted(tiempo_llegada_utc.c_str());
			ImGui::TextUnformatted(tiempo_epoch.c_str());
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
        ImGui::TextDisabled("Esperando selección de un paquete...");
    }
    ImGui::EndChild();


    ImGui::SameLine(); // Poner el Área 3 justo al lado del Área 2

    // --- ÁREA 3: CONTENIDO RAW (Hexadecimal y ASCII ) ---
    ImGui::BeginChild("Area3", ImVec2(0, 0), true);
    ImGui::TextUnformatted("AREA 3: CONTENIDO RAW DEL PAQUETE");
    ImGui::Separator();

    if (hay_seleccion && !paquete_actual.raw_data.empty()) {

        static int byte_resaltado = -1;
        bool algun_hover_este_frame = false;

        float pos_x_inicial = ImGui::GetCursorPosX();
        float offset_ascii = pos_x_inicial + 380.0f; // Ajustar si las columnas se empalman

        // Llamar a la herramienta de dibujo de ImGui
        ImDrawList* draw_list = ImGui::GetWindowDrawList();

        for (size_t i = 0; i < paquete_actual.raw_data.size(); i += 16) {
            ImGui::Text("%04X  ", (unsigned int)i);
            ImGui::SameLine(0, 0);

            // --- COLUMNA HEXADECIMAL ---
            for (size_t j = 0; j < 16; j++) {
                if (i + j < paquete_actual.raw_data.size()) {
                    unsigned char byte = paquete_actual.raw_data[i + j];

                    // Guardar las coordenadas de la pantalla para este número
                    ImVec2 pos_min = ImGui::GetCursorScreenPos();
                    ImGui::Text("%02X", byte);
                    ImVec2 pos_max = ImGui::GetItemRectMax();

                    if (ImGui::IsItemHovered()) {
                        byte_resaltado = (int)(i + j);
                        algun_hover_este_frame = true;
                    }

                    // Dibujar el bloque resaltador azul 
                    if (byte_resaltado == (int)(i + j)) {
                        draw_list->AddRectFilled(pos_min, pos_max, IM_COL32(0, 130, 255, 100));
                    }
                }
                else {
                    ImGui::Text("  ");
                }

                ImGui::SameLine(0, 0);
                if (j == 7) ImGui::Text("   ");
                else ImGui::Text(" ");
                ImGui::SameLine(0, 0);
            }

            // --- COLUMNA ASCII ---
            ImGui::SetCursorPosX(offset_ascii);

			ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 255, 255, 255)); // Color azul cian para el texto ASCII
            for (size_t j = 0; j < 16; j++) {
                if (i + j < paquete_actual.raw_data.size()) {
                    unsigned char byte = paquete_actual.raw_data[i + j];
                    char c = (byte >= 32 && byte <= 126) ? (char)byte : '.';

                    // Guardar las coordenadas de la letra
                    ImVec2 pos_min = ImGui::GetCursorScreenPos();
                    ImGui::Text("%c", c);
                    ImVec2 pos_max = ImGui::GetItemRectMax();

                    if (ImGui::IsItemHovered()) {
                        byte_resaltado = (int)(i + j);
                        algun_hover_este_frame = true;
                    }

                    // Aplicar el mismo bloque resaltador azul a la letra
                    if (byte_resaltado == (int)(i + j)) {
                        draw_list->AddRectFilled(pos_min, pos_max, IM_COL32(0, 130, 255, 100));
                    }
                }
                ImGui::SameLine(0, 0);
            }
			ImGui::PopStyleColor();
            ImGui::NewLine();
        }

        // Limpiar si quitamos el ratón del área
        if (!algun_hover_este_frame) {
            byte_resaltado = -1;
        }

    }
    else {
        ImGui::TextDisabled("Esperando seleccion de un paquete...");
    }

    ImGui::EndChild();

}


/*
* @brief Dibuja la interfaz gráfica utilizando ImGui. Controla dos vistas: selección de interfaz y análisis de tráfico.
*/
void dibujarInterfaz() {
    // Dimensiones inciales de la ventana 
    ImGui::SetNextWindowSize(ImVec2(1000, 700), ImGuiCond_FirstUseEver);
    ImGui::Begin("Sniffer de Red", nullptr, ImGuiWindowFlags_NoCollapse);

	establecer_estilo_general();

    if (!vista_analisis) {
		mostrar_pantalla_interfaz();
        if (!capturando) { filtro_captura[0] = '\0'; }
    }
    else {
		mostrar_pantalla_analisis();
        if (!capturando) { filtro_antes_captura[0] = '\0'; }
    }

    ImGui::End();
}

