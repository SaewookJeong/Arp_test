#include <pcap/pcap.h>
#include <libnet.h>
#include <netinet/in.h>


struct libnet_arp_hdr_Saewook
{
    uint16_t ar_hrd;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
    uint16_t ar_pro;         /* format of protocol address */
    uint8_t  ar_hln;         /* length of hardware address */
    uint8_t  ar_pln;         /* length of protocol addres */
    uint16_t ar_op;          /* operation type */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
    /* address information allocated dynamically */

    uint8_t sender_HA[ETHER_ADDR_LEN];         /* attack of hardware address */
    uint8_t sender_ip[4];
    uint8_t target_HA[ETHER_ADDR_LEN];         /* victim of hardware address */
    uint8_t target_ip[4];
    uint8_t padding[18];
};



int main()

{
    char *dev, errbuf[PCAP_ERRBUF_SIZE]; /* The device to sniff on, Error string */

    /* Define the device */
    dev = pcap_lookupdev(errbuf); //find the dev
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", dev);

    pcap_t *handle; /* Session handle */

    /* Open the session in promiscuous mode */
      handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // dev session open
      if (handle == NULL) {
          fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
          return(2);
      }

      char send_buf[sizeof(libnet_ethernet_hdr) + sizeof(libnet_arp_hdr_Saewook)] =  {0,};
      libnet_ethernet_hdr* eth_hdr = (libnet_ethernet_hdr*)send_buf;

      // eth_hdr setting place
      // how to get the gateway mac address
      send_buf[0] = 0xFF;
      send_buf[1] = 0xFF;
      send_buf[2] = 0xFF;
      send_buf[3] = 0xFF;
      send_buf[4] = 0xFF;
      send_buf[5] = 0xFF;

      // Source Mac address
      send_buf[6] = 0x00;
      send_buf[7] = 0x50;
      send_buf[8] = 0x56;
      send_buf[9] = 0xeb;
      send_buf[10] = 0x12;
      send_buf[11] = 0x0b;

      //arp type setting
      eth_hdr -> ether_type = htons(ETHERTYPE_ARP); // send_buf[12] = 0x08, send_buf[13] = 0x06)
      // ====== end the ether setting ====== //

      libnet_arp_hdr_Saewook* arp_hdr = (libnet_arp_hdr_Saewook*)(send_buf + sizeof(libnet_ethernet_hdr));
          arp_hdr -> ar_hrd = htons(ARPHRD_ETHER); // send_buf[14] = 0x00, send_buf[15] = 0x01
          arp_hdr -> ar_pro = htons(ETHERTYPE_IP); // send_buf[16] = 0x08, send_buf[17] = 0x00
          arp_hdr -> ar_hln = 0x06; // send_buf[18] = 0x06;
          arp_hdr -> ar_pln = 0x04; // send_buf[19] = 0x04;
          arp_hdr -> ar_op = htons(ARPOP_REQUEST); //send_buf[20] = 0x01, send_buf[21] = 0x00

          arp_hdr -> sender_HA[0] = 0x00; //send_buf[22]
          arp_hdr -> sender_HA[1] = 0x50; //send_buf[23]
          arp_hdr -> sender_HA[2] = 0x56; //send_buf[24]
          arp_hdr -> sender_HA[3] = 0xeb; //send_buf[25]
          arp_hdr -> sender_HA[4] = 0x12; //send_buf[26]
          arp_hdr -> sender_HA[5] = 0x0b; //send_buf[27]

          arp_hdr -> sender_ip[0] = 0xc0; //send_buf[28]
          arp_hdr -> sender_ip[1] = 0xa8; //send_buf[29]
          arp_hdr -> sender_ip[2] = 0xdb; //send_buf[30]
          arp_hdr -> sender_ip[3] = 0x02; //send_buf[31]




          arp_hdr -> target_HA[0] = 0x00; //send_buf[32]
          arp_hdr -> target_HA[1] = 0x00; //send_buf[33]
          arp_hdr -> target_HA[2] = 0x00; //send_buf[34]
          arp_hdr -> target_HA[3] = 0x00; //send_buf[35]
          arp_hdr -> target_HA[4] = 0x00; //send_buf[36]
          arp_hdr -> target_HA[5] = 0x00; //send_buf[37]



          arp_hdr -> target_ip[0] = 0xc0; //send_buf[38]
          arp_hdr -> target_ip[1] = 0xa8; //send_buf[39]
          arp_hdr -> target_ip[2] = 0xdb; //send_buf[40]
          arp_hdr -> target_ip[3] = 0x80; //send_buf[41]


          for(int i = 42; i <= 59; i++)
          {
            arp_hdr -> padding[i] = 0x00;
          }

          pcap_sendpacket(handle, (u_char*)send_buf, (sizeof(libnet_ethernet_hdr) + sizeof(libnet_arp_hdr_Saewook)));
}