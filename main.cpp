#include <iostream>
#include <pcap.h>
#include <string>
#include <vector>
#include <memory> // para evitar fugas de memoria
#include <ws2tcpip.h> 
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

struct ip_header {
  unsigned char ip_vhl;
  unsigned char ip_tos;
  struct in_addr ip_src;  // IP origen 
  struct in_addr ip_dst;  // IP destino 
  unsigned char ip_p;
};

// Almacenamiento global de paquetes capturados
vector<Datos_Paquete> paquetes_capturados;
int id_paquete = 1;
int longitud_encabezado_de_red = 0;  // Longitud de los datos de la capa de enlace 

/*
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

  const u_char *ptr_a_red = packetd_ptr + longitud_encabezado_de_red; // PUNTERO  a la capa de red 
  struct ip_header *ip_hdr = (struct ip_header *)ptr_a_red;

  char packet_srcip[INET_ADDRSTRLEN]; 
  char packet_dstip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip_hdr->ip_src), packet_srcip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip_hdr->ip_dst), packet_dstip, INET_ADDRSTRLEN);

  record.src_ip = packet_srcip;
  record.dest_ip = packet_dstip;

  int packet_hlen = (ip_hdr->ip_vhl & 0x0F);
  const u_char *ptr_a_transporte = ptr_a_red + (4 * packet_hlen);    // PUNTERO A LA CAPA DE TRANSPORTE  

  // Protocolos del a capa de enlace
  

  // Protocolos de la capa de red 
  struct icmp_hdr *icmp_hdr;

  // Protocolos de la capa de transporte
  struct tcp_header *tcp_hdr;
  struct udp_header *udp_hdr;

  // Protcolos de la capa de aplicación 
  struct telnet_header *telnet_hdr;
  struct ssh_header *ssh_hdr;
  struct ftp_header *ftp_hdr;
  struct sftp_header *sftp_hdr;
  struct dns_header *dns_hdr;
  struct dhcp_header *dhcp_hdr;

  switch (ip_hdr->ip_p) {
    case IPPROTO_TCP:
      tcp_hdr = (struct tcp_header *)ptr_a_transporte;
      record.protocol = "TCP";
      record.src_port = ntohs(tcp_hdr->th_port);
      record.dest_port = ntohs(tcp_hdr->th_dport);
      break;
    case IPPROTO_TCP:
      tcp_hdr = (struct tcp_header *)ptr_a_transporte;
      record.protocol = "TCP";
      record.src_port = ntohs(tcp_hdr->th_port);
      record.dst_port = ntohs(tcp_hdr->th_dport);
      break;

  }

}

int main() {

  return 0; 
}