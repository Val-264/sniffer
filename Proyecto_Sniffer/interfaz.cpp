// Control de la interfaz gráfica 

#include "estructuras.h"
using namespace std;

static bool vista_analisis = false; // Bandera para controlar lo que se analiza en pantalla 
static int interfaz_seleccionada = 0;

// Variables para el filtro de captura
static bool filtro_activo = false; // Bandera para controlar si se ha aplicado un filtro de captura o no
static bool filtro_activo_en_captura = false;
static char filtro_antes_captura[256] = "";
static char filtro_captura[256] = "";
static string filtro_aplicado = "";
static bool coincide = true; // Mostrar todo el tráfico por defecto, pero si el usuario aplica un filtro, entonces solo mostrar los paquetes que coincidan con el filtro aplicado

// Variable compartidas entre área 1, 2 y 3 
static int indice_paquete_seleccionado = -1;     // Variable para recordar qué paquete (fila) seleccionó el usuario
// Hacer una copia segura del paquete seleccionado para no mantener el candado cerrado mucho tiempo
static bool hay_seleccion = false;
Datos_Paquete paquete_actual;

namespace fs = std::filesystem;

// Banderas para controlar la exportación de tráfico a CSV
static bool exportar = false;

static bool contenido_por_default = false;
static bool contenido_personalizado = false;
static bool personalizar = false;
static bool contenido_filtrado = false;
static bool exportacion_seleccionada = false;
static bool exportacion_exitosa = false;

static bool nombre_csv_vacio = false;

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


// =======================================================================================================================================
//                                                      FUNCIONES COMPARTIDAS POR AMBAS INTERAFACES 
// =======================================================================================================================================

// *@brief Estilo aplicable a toda la interfaz 
void establecer_estilo_general() {
    ImGuiStyle& estilo_gral = ImGui::GetStyle();

    // Redondear botones 
    estilo_gral.FrameRounding = 5.0f;

	// Redondear ventanas emergentes 
    estilo_gral.ChildRounding = 5.0f;
    estilo_gral.PopupRounding = 5.0f;
}

void cambiar_tema_obscuro() {
	if (ImGui::Button("Tema obscuro")) {
		ImGui::StyleColorsDark();
        tema_claro = false;
		tema_obscuro = true;
	}
}

void cambiar_tema_claro() {
    if (ImGui::Button("Tema claro")) {
        ImGui::StyleColorsLight();
        tema_claro = true;
        tema_obscuro = false;
    }
}

// @breif Abre la interfaz de red seleccionada por el usuario para iniciar la captura de paquetes, 
// configurando el filtro de captura BPF si el usuario escribió un filtro antes de iniciar la captura, 
// y obteniendo la longitud del encabezado de enlace para procesar correctamente los paquetes capturados 
// dependiendo del tipo de enlace de la interfaz seleccionada
bool abrir_y_configurar_interfaz() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    string device_name = lista_interfaces_de_red[interfaz_seleccionada].nombre_tecnico;

    capdev = pcap_open_live(device_name.c_str(), BUFSIZ, 1, 1000, error_buffer);

    if (capdev == nullptr) {
        cerr << "ERR: No se pudo abrir la interfaz " << device_name << ": " << error_buffer << "\n";
        return false;
    }

    int link_hdr_type = pcap_datalink(capdev);
    longitud_encabezado_de_red = (link_hdr_type == DLT_NULL) ? 4 : (link_hdr_type == DLT_EN10MB) ? 14 : 0;

    struct bpf_program bpf;
    if (pcap_compile(capdev, &bpf, filtro_antes_captura, 0, 0) != PCAP_ERROR) {
        pcap_setfilter(capdev, &bpf);
    }
    else {
        cerr << "ERR: No se pudo compilar el filtro BPF: " << pcap_geterr(capdev) << "\n";
    }

    return true;
}

// =======================================================================================================================================
//                                                      PANTALLA 1: SELECCIÓN DE INTERFAZ 
// =======================================================================================================================================

void mostrar_tooltip_filtro_bpf() {
    ImGui::BeginTooltip();
    ImGui::Text("Filtro de captura Berkeley Packet Filter (BPF)");
    ImGui::Separator();
    ImGui::Text("Sintaxis:");
    ImGui::Separator();
    ImGui::Text("Por protocolo:");
    ImGui::BulletText("tcp");
    ImGui::BulletText("udp");
    ImGui::BulletText("icmp");
    ImGui::BulletText("arp");
    ImGui::Separator();
    ImGui::Text("Por puerto:");
    ImGui::BulletText("port 80");
    ImGui::BulletText("tcp port 443");
    ImGui::BulletText("udp port 53");
    ImGui::BulletText("portrange 1-1024");
    ImGui::Separator();
    ImGui::Text("Por direccion:");
    ImGui::BulletText("host 192.168.1.1");
    ImGui::BulletText("src host 10.0.0.5");
    ImGui::BulletText("dst host 8.8.8.8");
    ImGui::BulletText("net 192.168.1.0/24");
    ImGui::Separator();
    ImGui::Text("Por MAC:");
    ImGui::BulletText("ether host aa:bb:cc:dd:ee:ff");
    ImGui::BulletText("ether src 11:22:33:44:55:66");
    ImGui::Separator();
    ImGui::Text("Combinaciones:");
    ImGui::BulletText("tcp and port 80");
    ImGui::BulletText("udp or tcp");
    ImGui::BulletText("not arp");
    ImGui::BulletText("src host 192.168.1.1 and tcp");
    ImGui::Separator();
    ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.3f, 1.0f), "Se aplica antes de capturar.");
    ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.3f, 1.0f), "Solo se capturan los paquetes que coinciden.");
    ImGui::EndTooltip();
}

// @brief Dibuja la pantalla de selección de interfaz, permitiendo al usuario elegir una interfaz de red para iniciar la captura de paquetes
void mostrar_pantalla_interfaz() {

	cambiar_tema_obscuro();
	ImGui::SameLine();
    cambiar_tema_claro();
    ImGui::Separator();

    ImGui::Text("BIENVENIDO AL ANALIZADOR DE TRAFICO\n\nSELECCIONA UNA INTERFAZ PARA COMENZAR\n");
    ImGui::Separator();
    ImGui::Spacing();

    // Filtro de captura bpf opcional para que el usuario pueda escribir un filtro antes de iniciar la captura 
    ImGui::Text("Filtro (Puedes configurar un filtro antes de comenzar la captura):");
    float ancho_input = ImGui::GetContentRegionAvail().x * 0.8f;
    if (ancho_input < 200.0f) ancho_input = 200.0f; // mínimo
    ImGui::SetNextItemWidth(ancho_input);
    ImGui::InputText("##FiltroBPF", filtro_antes_captura, IM_ARRAYSIZE(filtro_antes_captura));
    ImGui::Spacing();
    // Tooltip de ayuda para filtro BPF
    if (ImGui::IsItemHovered()) {
		mostrar_tooltip_filtro_bpf();
    }

    ImGui::Text("Interfaces disponibles:");
    ImGui::SetNextItemWidth(500);

    if (!lista_interfaces_de_red.empty()) {
        string preview_actual = lista_interfaces_de_red[interfaz_seleccionada].descripcion;
        bool hay_seleccion = false;
        // Estandatizar el tamaño de los botones para que se vean uniformes
        float ancho_boton = ImGui::GetContentRegionAvail().x * 0.85f;
        if (ancho_boton > 500.0f) ancho_boton = 500.0f; // máximo
        ImVec2 tamanio_boton = ImVec2(ancho_boton, 30.0f);
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
			if (abrir_y_configurar_interfaz()) {
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

// =======================================================================================================================================
//                                                      PANTALLA 2: ANÁLISIS DE TRÁFICO
// =======================================================================================================================================

// *@brief Limpiar banderas de exportacion para no afectar a la siguiente exportacion
void limpiar_banderas_exportacion() {
    exportar = false;
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
    // Si no hay filtro, mostrar todo
    if (filtro_aplicado.empty()) {
        coincide = true;
        return;
    }

    // Copia del filtro en minúsculas
    string filtro = filtro_aplicado;
    for (auto& c : filtro) c = tolower(c);

    // Datos del paquete
    string prot = paquetes_capturados[i].protocolo;
    for (auto& c : prot) c = tolower(c);

    string ip_src = paquetes_capturados[i].src_ip;
    string ip_dst = paquetes_capturados[i].dest_ip;
    string p_src = to_string(paquetes_capturados[i].src_port);
    string p_dst = to_string(paquetes_capturados[i].dest_port);

    // MAC en minúsculas (para comparar sin sensibilidad)
    string mac_src = ip_src;
    for (auto& c : mac_src) c = tolower(c);
    string mac_dst = ip_dst;
    for (auto& c : mac_dst) c = tolower(c);

    // Buscar operador ==
    size_t pos_eq = filtro.find("==");

    if (pos_eq != string::npos) {
        // --- Formato: clave == valor ---
        string clave = filtro.substr(0, pos_eq);
        string valor = filtro.substr(pos_eq + 2);

        // Trim de clave y valor
        auto trim = [](string& s) {
            s.erase(0, s.find_first_not_of(" \t"));
            s.erase(s.find_last_not_of(" \t") + 1);
            };
        trim(clave);
        trim(valor);

        // Valor en minúsculas para comparaciones de texto
        string valor_lower = valor;
        for (auto& c : valor_lower) c = tolower(c);

        // --- IP fuente (coincidencia exacta) ---
        if (clave == "ip.src") {
            coincide = (ip_src == valor);
            return;
        }

        // --- IP destino (coincidencia exacta) ---
        if (clave == "ip.dst") {
            coincide = (ip_dst == valor);
            return;
        }

        // --- MAC fuente (coincidencia exacta, sin sensibilidad a mayúsculas) ---
        if (clave == "mac.src") {
            coincide = (mac_src == valor_lower);
            return;
        }

        // --- MAC destino ---
        if (clave == "mac.dst") {
            coincide = (mac_dst == valor_lower);
            return;
        }

        // --- Puerto TCP origen ---
        if (clave == "tcp.srcport") {
            coincide = (p_src == valor);
            return;
        }

        // --- Puerto TCP destino ---
        if (clave == "tcp.dstport") {
            coincide = (p_dst == valor);
            return;
        }

        // --- Puerto UDP origen ---
        if (clave == "udp.srcport") {
            coincide = (p_src == valor);
            return;
        }

        // --- Puerto UDP destino ---
        if (clave == "udp.dstport") {
            coincide = (p_dst == valor);
            return;
        }

        // --- Puerto TCP (origen o destino) ---
        if (clave == "tcp.port") {
            coincide = (p_src == valor || p_dst == valor);
            return;
        }

        // --- Puerto UDP (origen o destino) ---
        if (clave == "udp.port") {
            coincide = (p_src == valor || p_dst == valor);
            return;
        }

        // --- Protocolo (estructurado) ---
        if (clave == "protocolo") {
            coincide = (prot == valor_lower);
            return;
        }

        // Clave no reconocida
        coincide = false;
        return;
    }
    else {
        // --- Formato: solo nombre de protocolo ---
        auto trim = [](string& s) {
            s.erase(0, s.find_first_not_of(" \t"));
            s.erase(s.find_last_not_of(" \t") + 1);
            };
        trim(filtro);

        coincide = (prot == filtro);
        return;
    }
}


// @brief Dibuja el botón para volver a la pantalla de selección de interfaz, deteniendo la 
// captura de paquetes si aún está activa y limpiando la lista de paquetes capturados para 
// evitar mostrar tráfico antiguo al volver a iniciar una nueva captura desde la pantalla de 
// selección de interfaz 
void mostrar_btn_volver_interfaces () {
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

		// Limpiar filtros de captura para no afectar la próxima captura
        if (!capturando) { filtro_captura[0] = '\0'; }
        if (!capturando) { filtro_antes_captura[0] = '\0'; }

        vista_analisis = false;
    }

}

/*
@brief Dibuja el botón para detener la captura de paquetes, deteniendo la captura si aún está 
activa y permitiendo al usuario analizar el tráfico capturado hasta el momento sin cerrar la 
sesión de análisis de tráfico ni volver a la pantalla de selección de interfaz
*/ 
void mostrar_btn_detener() {
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.8f, 0.0f, 0.0f, 1.0f));
    if (ImGui::Button("Detener")) {
        if (capturando) {
            capturando = false;
            if (capdev != nullptr) pcap_breakloop(capdev);
            if (hilo_de_captura.joinable()) hilo_de_captura.join();
            if (capdev != nullptr) { pcap_close(capdev); capdev = nullptr; }
        }
    }
    ImGui::PopStyleColor();
}

/*
@brief Dibuja el botón para reiniciar la captura, deteniendo la captura si aún está activa y 
limpiando la lista de paquetes capturados para empezar una nueva sesión de captura sin tener 
que volver a la pantalla de selección de interfaz
*/
void reiniciar_Captura() {
    if (ImGui::Button("Reiniciar captura")) {
        if (!capturando) {
            if (abrir_y_configurar_interfaz()) {
                {
                    lock_guard<mutex> lock(mutex_paquetes); // Asegurar que no haya acceso concurrente a la lista de paquetes
                    paquetes_capturados.clear();
                    id_paquete = 0;
                }
                capturando = true;
                hilo_de_captura = thread(captura_de_paquetes);
            }
        }
    }
}

/*
@brief Maneja la lógica de activación y desactivación de filtros de captura, 
aplicando el filtro escrito por el usuario en la interfaz gráfica para mostrar 
solo los paquetes que coincidan con el filtro aplicado, o mostrando todo el 
tráfico si no hay ningún filtro aplicado
*/ 
void manejar_filtros_en_captura() {
    if (!filtro_activo && strlen(filtro_captura) > 0) {
        filtro_activo = true;
    }
    else if (filtro_activo && strlen(filtro_captura) == 0) {
        filtro_activo = false;
    }

    ImGui::SameLine();

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
}
 
/*
@brief Maneja la lógica de exportación de tráfico a CSV, permitiendo al usuario elegir 
entre exportar todo el tráfico con un formato por default, personalizar el contenido a 
exportar seleccionando las columnas que desea incluir en el CSV, o exportar solo el 
tráfico que coincida con el filtro aplicado en la captura, y luego capturar el nombre 
del archivo a exportar y generar el archivo CSV con el contenido seleccionado por el usuario
*/
void manejar_exportacion() {
    static char nombre_archivo[256] = "";
    static char carpeta_exportacion[500] = "";

    if (ImGui::Button("Exportar")) {
        if (!capturando) {
            exportar = true;
        }
    }

    if (exportar) {

        // Contenido de la ventana emergente 
        if (!exportacion_seleccionada) {
            ImGui::OpenPopup("Configurar exportacion");
            if (ImGui::BeginPopupModal("Configurar exportacion", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {

                if (ImGui::Selectable(">> Contenido por default")) {
                    contenido_por_default = true;
                    contenido_personalizado = false;
                    contenido_filtrado = false;
                    exportacion_seleccionada = true;
                    ImGui::CloseCurrentPopup();
                }
                // Tooltip para "Contenido por default"
                if (ImGui::IsItemHovered()) {
                    ImGui::BeginTooltip();
                    ImGui::Text("Exporta todas las columnas:");
                    ImGui::Separator();
                    ImGui::BulletText("No.");
                    ImGui::BulletText("Protocolo");
                    ImGui::BulletText("Origen (IP/MAC)");
                    ImGui::BulletText("Destino (IP/MAC)");
                    ImGui::BulletText("Puerto Origen");
                    ImGui::BulletText("Puerto Destino");
                    ImGui::BulletText("Longitud (Bytes)");
                    ImGui::BulletText("Tiempo Local");
                    ImGui::BulletText("Tiempo UTC");
                    ImGui::BulletText("Tiempo Epoch");
                    ImGui::Separator();
                    ImGui::Text("Incluye todos los paquetes capturados.");
                    ImGui::EndTooltip();
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
                    limpiar_banderas_exportacion();
                    exportar = false;
                    ImGui::CloseCurrentPopup();
                }

                ImGui::EndPopup();
            }
        }

        if (personalizar) {
            ImGui::OpenPopup("Personalizar");
            if (ImGui::BeginPopupModal("Personalizar", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
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
                    if (!no_columna && !protocolo_columna && !origen_columna && !destino_columna && !puerto_origen_columna
                        && !puerto_destino_columna && !longitud_columna && !tiempo_local_columna && !tiempo_utc_columna
                        && !tiempo_epoch_columna) {
                        exportar = false;
                        limpiar_banderas_exportacion();
                    }

                    ImGui::CloseCurrentPopup();

                }
                if (ImGui::Button("Cancelar")) {

                    limpiar_banderas_exportacion();
                    exportar = false;
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }
        }

        // Configurar carpeta de exportación en Documentos del usuario
        char ruta_documentos[MAX_PATH] = "";
        if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PERSONAL, nullptr, 0, ruta_documentos))) {
            snprintf(carpeta_exportacion, sizeof(carpeta_exportacion),
                "%s\\Sniffer_Exportaciones\\", ruta_documentos);
        }
        else {
            strcpy_s(carpeta_exportacion, sizeof(carpeta_exportacion), "exportaciones_csv\\");
        }

        // Nombre del archivo
        ImGui::SameLine();
        ImGui::Text("Nombre archivo:"); ImGui::SameLine();
        ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.4f);
        ImGui::InputText("##NombreArchivo", nombre_archivo, IM_ARRAYSIZE(nombre_archivo));
        ImGui::SameLine();
        ImGui::TextDisabled(".csv");

        if (ImGui::Button("Guardar CSV")) {

            if (strlen(nombre_archivo) == 0) {
                nombre_csv_vacio = true;
                ImGui::OpenPopup("Nombre de archivo requerido");
            }
            else {
                nombre_csv_vacio = false;

                if (!fs::exists(carpeta_exportacion)) {
                    fs::create_directories(carpeta_exportacion);
                }

                string ruta_completa = string(carpeta_exportacion) + nombre_archivo + ".csv";
                ofstream archivo(ruta_completa);
                if (archivo.is_open()) {
                    exportar = false;

                    if (contenido_por_default) {
                        archivo << "No.,Protocolo,Origen,Destino,Puerto Origen,Puerto Destino,Longitud (Bytes),Tiempo Local,Tiempo UTC,Tiempo Epoch\n";

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
                        archivo << "No.,Protocolo,Origen,Destino,Puerto Origen,Puerto Destino,Longitud (Bytes),Tiempo Local,Tiempo UTC,Tiempo Epoch\n";
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
                                filtrar_trafico(pkt.id - 1);
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
                    nombre_archivo[0] = '\0';
                    exportacion_exitosa = true;
                    cout << "Exportacion exitosa. Archivo creado en: " << ruta_completa << "\n";
                }
                else {
                    ImGui::OpenPopup("Fallo al exportar");
                    if (ImGui::BeginPopupModal("Fallo al exportar", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
                        ImGui::TextUnformatted("No se pudo crear el archivo CSV");
                        ImGui::Spacing();
                        if (ImGui::Button("OK", ImVec2(80.0f, 30.0f))) {
                            limpiar_banderas_exportacion();
                            ImGui::CloseCurrentPopup();
                        }
                        ImGui::EndPopup();
                    }
                    cerr << "ERR: No se pudo crear el archivo CSV.\n";
                }
            }
        }

        ImGui::SameLine();
        if (ImGui::Button("Cancelar exportacion")) {
            exportar = false;
            limpiar_banderas_exportacion();
        }
    }

    if (nombre_csv_vacio) {
        ImGui::OpenPopup("Nombre de archivo requerido");
        if (ImGui::BeginPopupModal("Nombre de archivo requerido", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::TextUnformatted("Por favor ingresa un nombre para el archivo CSV.");
            ImGui::Spacing();
            if (ImGui::Button("OK", ImVec2(80.0f, 30.0f))) {
                nombre_csv_vacio = false;
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
    }

    if (exportacion_exitosa) {
        ImGui::OpenPopup("Exportacion Exitosa");
        if (ImGui::BeginPopupModal("Exportacion Exitosa", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::TextUnformatted("Trafico exportado exitosamente al CSV");
            ImGui::Spacing();
            if (ImGui::Button("OK", ImVec2(80.0f, 30.0f))) {
                limpiar_banderas_exportacion();
                exportacion_exitosa = false;
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
    }
}

// @brief Devuelve un color específico para cada protocolo, utilizado para colorear las filas de la tabla 
// de análisis de tráfico y mejorar la visualización del tráfico capturado, aplicando una transparencia para 
// que los colores no sean demasiado intensos y permitan distinguir fácilmente los diferentes protocolos en la tabla
ImVec4 obtener_color_protocolo(const std::string& protocolo) {
    // Transparencia
    float alpha = (tema_obscuro) ? 0.50f : 0.25f; 

    if (protocolo == "HTTP" || protocolo == "HTTPS")
        return ImVec4(0.20f, 0.55f, 0.95f, 0.25f); // Azul suave
    else if (protocolo == "DNS")
        return ImVec4(0.95f, 0.75f, 0.15f, 0.25f); // Ámbar suave
    else if (protocolo == "TCP")
        return ImVec4(0.30f, 0.70f, 0.45f, 0.25f); // Verde suave
    else if (protocolo == "UDP")
        return ImVec4(0.60f, 0.50f, 0.85f, 0.25f); // Violeta suave
    else if (protocolo == "ICMPv4" || protocolo == "ICMPv6")
        return ImVec4(0.95f, 0.45f, 0.25f, 0.25f); // Naranja suave
    else if (protocolo == "ARP")
        return ImVec4(0.65f, 0.65f, 0.65f, 0.25f); // Gris medio
    else if (protocolo == "SSH")
        return ImVec4(0.25f, 0.75f, 0.80f, 0.25f); // Cian suave
    else if (protocolo == "DHCP")
        return ImVec4(0.80f, 0.40f, 0.70f, 0.25f); // Rosa suave
    else if (protocolo == "FTP" || protocolo == "Telnet")
        return ImVec4(0.70f, 0.55f, 0.35f, 0.25f); // Marrón suave
    else
        return ImVec4(0.40f, 0.40f, 0.40f, 0.15f); // Gris neutro para otros
}

// @brief Dibuja el área de la tabla que muestra el tráfico capturado, aplicando el filtro de captura 
// si está activo para mostrar solo los paquetes que coincidan con el filtro aplicado, y permitiendo 
// al usuario seleccionar un paquete para mostrar su información detallada en el área de información estructurada
void mostrar_area_1(float ancho_total, float alto_total) {
    float alto_area1 = alto_total * 0.55f;
    ImGui::BeginChild("Area1", ImVec2(ancho_total, alto_area1), true);

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
        ImGui::TableSetupColumn("Origen", ImGuiTableColumnFlags_WidthStretch);      
        ImGui::TableSetupColumn("Destino", ImGuiTableColumnFlags_WidthStretch);     
        ImGui::TableSetupColumn("Puertos(src->dest)", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Longitud", ImGuiTableColumnFlags_WidthFixed, 70.0f);

        bool scroll_fondo = (ImGui::GetScrollY() >= ImGui::GetScrollMaxY());

        // Recorrer el  vector global para dibujar cada paquete capturado
        {
            lock_guard<mutex> lock(mutex_paquetes); // Aseguramos que no haya acceso concurrente a la lista de paquetes

            for (int i = 0; i < paquetes_capturados.size(); i++) {
                filtrar_trafico(i);
                // Si el paquete no cumple con el filtro, saltar a la siguiente iteración sin dibujarlo
                if (!coincide) continue;

                ImGui::TableNextRow();

				// Asiganar color según el protocolo para mejorar la visualización del tráfico en la tabla
                ImVec4 color_fila = obtener_color_protocolo(paquetes_capturados[i].protocolo);
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::ColorConvertFloat4ToU32(color_fila));

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


    {
        lock_guard<mutex> lock(mutex_paquetes);
        if (indice_paquete_seleccionado >= 0 && indice_paquete_seleccionado < paquetes_capturados.size()) {
            paquete_actual = paquetes_capturados[indice_paquete_seleccionado];
            hay_seleccion = true;
        }
    }

}

void mostrar_area_2(float ancho_total) {
    ImGui::BeginChild("Area2", ImVec2(ancho_total * 0.5f, -1), true);
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
                ImGui::TextUnformatted("Tipo de protocolo: ARP (0x0806)");
            }
            else if (paquete_actual.protocolo == "IPv6" || paquete_actual.protocolo == "ICMPv6") {
                ImGui::TextUnformatted("Tipo de protcolo: IPv6 (0x86DD)");
            }
            else {
                ImGui::TextUnformatted("Tipo de protocolo: IPv4 (0x0800)");
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
                ImGui::TextUnformatted("Tipo de protcolo: IPv4 (0x0800)");
                ImGui::TextUnformatted("Hardware size: 6");
                ImGui::TextUnformatted("Protocol size: 4");

                ImGui::TextUnformatted(("Direccion MAC origen: " + paquete_actual.src_ip).c_str());
                ImGui::TextUnformatted(("Direccion MAC destino: " + paquete_actual.dest_ip).c_str());

                ImGui::TreePop();
            }
        }
    }
    else {
        ImGui::TextDisabled("Esperando selección de un paquete...");
    }
    ImGui::EndChild();

}

void mostrar_area_3() {
    ImGui::BeginChild("Area3", ImVec2(0, -1), true);
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
						draw_list->AddRectFilled(pos_min, pos_max, IM_COL32(255, 255, 255, 255));
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

            if (tema_obscuro) ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 255, 255, 255)); // Color azul cian para el texto ASCII
			if (tema_claro) ImGui::PushStyleColor(ImGuiCol_Text, (IM_COL32(0, 140, 0, 255))); // Color azul para el texto ASCII
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
            if (tema_obscuro) ImGui::PopStyleColor();
			if (tema_claro)   ImGui::PopStyleColor();
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

// @brief Dibuja la pantalla de análisis de tráfico, mostrando la lista de paquetes capturados y detalles del paquete seleccionado
void mostrar_pantalla_analisis() {

    // --- BARRA DE HERRAMIENTAS SUPERIOR ---
	mostrar_btn_volver_interfaces();

	ImGui::SameLine();
    cambiar_tema_obscuro();

    ImGui::SameLine();
	cambiar_tema_claro();

    ImGui::Separator();
	mostrar_btn_detener();


    ImGui::SameLine();
	reiniciar_Captura();

    ImGui::SameLine();
    ImGui::Text(" | Filtro:"); ImGui::SameLine();
    float ancho_filtro = ImGui::GetContentRegionAvail().x * 0.3f;
    if (ancho_filtro < 150.0f) ancho_filtro = 150.0f;
    ImGui::SetNextItemWidth(ancho_filtro);
    ImGui::InputText("##Filtro", filtro_captura, IM_ARRAYSIZE(filtro_captura));

    // Tooltip de ayuda
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::Text("Formatos aceptados:");
        ImGui::Separator();
        ImGui::Text("Solo protocolo: HTTP, DNS, TCP, UDP, ARP, SSH...");
        ImGui::Separator();
        ImGui::Text("Clave == valor:");
        ImGui::BulletText("ip.src == 192.168.1.5");
        ImGui::BulletText("ip.dst == 10.0.0.1");
        ImGui::BulletText("mac.src == aa:bb:cc:dd:ee:ff");
        ImGui::BulletText("mac.dst == 11:22:33:44:55:66");
        ImGui::BulletText("tcp.srcport == 443");
        ImGui::BulletText("tcp.dstport == 80");
        ImGui::BulletText("udp.srcport == 53");
        ImGui::BulletText("udp.dstport == 67");
        ImGui::BulletText("tcp.port == 22");
        ImGui::BulletText("udp.port == 53");
        ImGui::BulletText("protocolo == TCP");
        ImGui::EndTooltip();
    }

	manejar_filtros_en_captura();

    ImGui::Separator();
	manejar_exportacion();

    ImGui::Separator();

    // Calcular el espacio disponible
    float ancho_total = ImGui::GetContentRegionAvail().x;
    float alto_total = ImGui::GetContentRegionAvail().y;

    // --- ÁREA 1: TRÁFICO CAPTURADO (Lista de Paquetes) ---
	mostrar_area_1(ancho_total, alto_total);

    // --- ÁREA 2: INFORMACIÓN ESTRUCTURADA ---
	mostrar_area_2(ancho_total);

    ImGui::SameLine(); // Poner el Área 3 justo al lado del Área 2

    // --- ÁREA 3: CONTENIDO RAW (Hexadecimal y ASCII ) ---
	mostrar_area_3();
}


/*
* @brief Dibuja la interfaz gráfica utilizando ImGui. Controla dos vistas: selección de interfaz y análisis de tráfico.
*/
void dibujarInterfaz() {
    // Obtener el tamaño de la ventana GLFW
    int ancho_ventana, alto_ventana;
    GLFWwindow* ventana_actual = glfwGetCurrentContext();
    glfwGetWindowSize(ventana_actual, &ancho_ventana, &alto_ventana);

    // Posicionar y dimensionar la ventana principal de ImGui
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImVec2((float)ancho_ventana, (float)alto_ventana));

    ImGuiWindowFlags flags_ventana = ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoBringToFrontOnFocus;

    ImGui::Begin("Sniffer de Red", nullptr, flags_ventana);

    establecer_estilo_general();

    if (!vista_analisis) {
        mostrar_pantalla_interfaz();
    }
    else {
        mostrar_pantalla_analisis();
    }

    ImGui::End();
}

