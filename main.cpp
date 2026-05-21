#include "estructuras.h"

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
  icmp_header *icmp_hdr;

  // Protocolos de la capa de transporte
  tcp_header *tcp_hdr;
  udp_header *udp_hdr;

  // Protcolos de la capa de aplicación 
  dns_header *dns_hdr;
  dhcp_header *dhcp_hdr;

  switch (ip_hdr->ip_p) {
    case IPPROTO_TCP:
      tcp_hdr = (struct tcp_header *)ptr_a_transporte;
      record.protocol = "TCP";
      record.src_port = ntohs(tcp_hdr->th_sport);
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