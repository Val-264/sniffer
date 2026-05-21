#ifndef ESTRUCTURAS_H
#define ESTRUCTURAS_H
#include <iostream>
#include <pcap.h>
#include <string>
#include <sstream>
#include <vector>
#include <memory> // para evitar fugas de memoria
#include <ws2tcpip.h> 
#include <iomanip> // Para impresión uniforme de columnas 
using namespace std;

struct Datos_Paquete {
  int id; 
  int longitud_paquete;
  string src_ip;
  string dest_ip;
  string protocol; 

  int src_port = 0;
  int dest_port = 0;

  string extra_info;

  vector<unsigned char> raw_data;
};

// ==========================================
// PROTOCOLOS DE LA CAPA DE ENLACE (Capa 2)
// ==========================================

// Encabezado Ethernet (14 bytes)
struct eth_header {
    unsigned char dest_mac[6]; // Dirección MAC Destino
    unsigned char src_mac[6];  // Dirección MAC Origen
    unsigned short eth_type;   // Tipo de protocolo (ej. 0x0800 para IPv4, 0x0806 para ARP)
};

// Encabezado ARP (Address Resolution Protocol)
struct arp_header {
    unsigned short hw_type;    // Tipo de hardware (Ethernet = 1)
    unsigned short prot_type;  // Tipo de protocolo (IPv4 = 0x0800)
    unsigned char hw_len;      // Longitud de dirección de hardware (6)
    unsigned char prot_len;    // Longitud de dirección de protocolo (4)
    unsigned short opcode;     // Código de operación (1 = Request, 2 = Reply)
    unsigned char sender_mac[6]; // MAC del remitente
    unsigned char sender_ip[4];  // IP del remitente
    unsigned char target_mac[6]; // MAC del destino
    unsigned char target_ip[4];  // IP del destino
};


// ==========================================
// PROTOCOLOS DE LA CAPA DE RED (Capa 3)
// ==========================================

// Encabezado IPv4 
struct ip_header {
    unsigned char  ip_vhl;     // Versión y longitud del encabezado
    unsigned char  ip_tos;     // Tipo de servicio
    unsigned short ip_len;     // Longitud total
    unsigned short ip_id;      // Identificación
    unsigned short ip_off;     // Fragmento
    unsigned char  ip_ttl;     // Tiempo de vida (TTL)
    unsigned char  ip_p;       // Protocolo
    unsigned short ip_sum;     // Checksum
    struct in_addr ip_src;     // IP origen
    struct in_addr ip_dst;     // IP destino
};

// Encabezado IPv6 
struct ipv6_header {
    unsigned int   vtc_flow;    // Versión, Clase de Tráfico y Etiqueta de Flujo
    unsigned short payload_len; // Longitud del contenido (payload)
    unsigned char  next_header; // Siguiente encabezado (equivalente a ip_p en IPv4)
    unsigned char  hop_limit;   // Límite de saltos (equivalente a TTL)
    struct in6_addr ip_src;     // IP origen (16 bytes)
    struct in6_addr ip_dst;     // IP destino (16 bytes)
};

// Encabezado ICMP
struct icmp_header {
    unsigned char  icmp_type;  // Tipo de mensaje (ej. 8 = Echo Request, 0 = Echo Reply)
    unsigned char  icmp_code;  // Código específico
    unsigned short icmp_cksum; // Suma de comprobación
    unsigned short icmp_id;    // Identificador
    unsigned short icmp_seq;   // Número de secuencia
};


// ==========================================
// PROTOCOLOS DE LA CAPA DE TRANSPORTE (Capa 4)
// ==========================================

// Encabezado TCP
struct tcp_header {
    unsigned short th_sport;            // Puerto origen
    unsigned short th_dport;            // Puerto destino
    unsigned int   th_seq;              // Número de secuencia
    unsigned int   th_ack;              // Número de acuse de recibo
    unsigned char  th_x2:4, th_off:4;   // Reserved y Data Offset
    unsigned char  th_flags;            // Banderas (SYN, ACK, PSH, FIN, etc.)
    unsigned short th_win;              // Tamaño de ventana
    unsigned short th_sum;              // Checksum
    unsigned short th_urp;              // Puntero urgente
};

// Constantes para leer las banderas TCP
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20

// Encabezado UDP
struct udp_header {
    unsigned short uh_sport;   // Puerto origen
    unsigned short uh_dport;   // Puerto destino
    unsigned short uh_ulen;    // Longitud total de UDP
    unsigned short uh_sum;     // Checksum
};


// ==========================================
// PROTOCOLOS DE LA CAPA DE APLICACIÓN (Capa 7)
// ==========================================

// Encabezado DNS (Se monta sobre UDP)
struct dns_header {
    unsigned short id;         // Identificador de transacción
    unsigned short flags;      // Banderas DNS
    unsigned short q_count;    // Número de preguntas
    unsigned short ans_count;  // Número de respuestas
    unsigned short auth_count; // Número de registros de autoridad
    unsigned short add_count;  // Número de registros adicionales
};

// Encabezado DHCP (Se monta sobre UDP)
struct dhcp_header {
    unsigned char  op;         // Código de mensaje (1 = Request, 2 = Reply)
    unsigned char  htype;      // Tipo de hardware
    unsigned char  hlen;       // Longitud del hardware
    unsigned char  hops;       // Saltos
    unsigned int   xid;        // ID de transacción
    unsigned short secs;       // Segundos transcurridos
    unsigned short flags;      // Banderas
    struct in_addr ciaddr;     // IP del cliente
    struct in_addr yiaddr;     // IP asignada al cliente ("Your IP")
    struct in_addr siaddr;     // IP del servidor
    struct in_addr giaddr;     // IP del agente de relevo
    unsigned char  chaddr[16]; // MAC del cliente
    unsigned char  sname[64];  // Nombre del servidor
    unsigned char  file[128];  // Nombre del archivo de boot
    unsigned int   magic_cookie; // Cookie mágica (siempre es 0x63825363)
    // Después de esto vienen las opciones de DHCP dinámicas
};

// ==========================================
// VARIABLES GLOBALES 
// ==========================================
// Almacenamiento global de paquetes capturados
vector<Datos_Paquete> paquetes_capturados;
inline int id_paquete = 1;
inline int longitud_encabezado_de_red = 0;  // Longitud de los datos de la capa de enlace 

#endif