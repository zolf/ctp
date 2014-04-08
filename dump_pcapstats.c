//// ==========================================================================================
// Just Another program to dump/extract data from pcap files. This to make a quick assessment
// you ask tshark ?, Yes Wireshark/Tshark are very, very nice tools, but not realy effective
// when you play with multi giga byte on cap files, and just want some high level info.
//
// Also implemented a weird storage structure to speedup things 
// 
// BUGS: i guess yes
//
// Restrictions: yes, it does what i want and need.
//       only wants ethernet or ethernet + vlan frames
//       only accepts ip v4 packets
// 
// flos@xs4all.nl 2013/10/14 
// Developed this on Ubuntu 12.04 64bits
// for Mac OS X install the Commandline toolchain from the dev site
// 
// build gcc dump_pcapstats -lpcap -o dump_pcapstats
//
// changes: 
//    0.1 just a POC
//    0.2 changed storage structure
//        added fields to count
//    0.3 added first and last time stamps and ttl
//    0.4 change output format for Pieter S
//        added this comments, to make it more readable
//    0.5 added some BPF stuff    
//    0.6 added ID and extended usage()
//    0.7 fixes :)
//    0.8 more fixes and ttl, src and dst map 
//
//// ==========================================================================================
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap.h>
#include<net/ethernet.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<time.h>
#include<limits.h>
#include<sys/resource.h>
#define VLAN_TAG_LEN 4        	// no clue if or where it's defined
#define IP_HDR_LEN 20        	// no clue if or where it's defined

#define DUMP_VERSION "0.8c"
unsigned long pkt_count  = 0;   // some overall counters. The packets seen
unsigned long data_count = 0;   // i full wire size of the packets
unsigned long host_count = 0;   // the number of uniq ip's seen


// function to process a packet, the packet comes from the pcap_loop
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

void usage(char *);


// the struct to store the details
typedef struct {
 struct timeval first;   // first seen
 struct timeval last;    // last seen
 unsigned long snd_packets;
 unsigned long snd_data;
 unsigned long rcv_packets;
 unsigned long rcv_data;
 unsigned long unknown;
 unsigned long tcp;
 unsigned long udp;
 unsigned long icmp;
 struct in_addr last_host;    // just remember the last host's packet
 unsigned short id;
 unsigned char ttl;
} sHost;

char header_printed = 0;
sHost *mapping_get_host(unsigned long);
int mapping_ip(unsigned long);
int mapping_init(void);
int mapping_print(void);
int mapping_free(void);
int mapping_print_record(u_char, u_char, u_char, u_char, sHost *h);
unsigned long  *****root = NULL;

struct bpf_program bpf_f;
char use_filter = 0;

// create a map of the TTL values seen
char ttlFlag = 0;
unsigned long *ttlMap = NULL;
// create a map of the sourceports seen
char srcFlag = 0;
unsigned long *srcMap = NULL;
// create a map of the dest ports seen
char dstFlag = 0;
unsigned long *dstMap = NULL;
// when multiple filenames
unsigned long fileCount = 0 ;

//// ==========================================================================================
// you guessed right; the entry point of the program
//
//// ==========================================================================================
main(int argc, char **argv)
{
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
char *filter = 0;
struct rusage musage;
char multi = 0;
int i;

    if(argc < 2){
        usage(argv[0]);
        return -1;
    }

    // initialize the storage structure
    if(mapping_init() == -1) { 
        fprintf(stderr, "ERROR: initializing\n");
	return -1; 
    }	

    for(i=1;i<argc;i++) {
         // options first
         if(argv[i][0] == '-') {
            switch(argv[i][1]) {
              default:
              case 'h':
                    usage(argv[0]);
                    return -1;

              case 'f':   // argument the bpf filter in quotes
                   if((i+2) < argc) {
                      filter=argv[i+1];
                      fprintf(stderr, "INFO: got filter: %s\n", filter); // 
                      i++;
                      if(pcap_compile_nopcap(60, DLT_EN10MB, &bpf_f, filter, 1, PCAP_NETMASK_UNKNOWN)) {
                      	fprintf(stderr, "ERROR: compiling filter : %s\n", filter); // 
                        return -1;
                      } 
                      use_filter = 1;
                   } else {
                     usage(argv[0]);
                     return -1;
                   }
                   break;

              case 't':  // create ttl map
		   ttlFlag++;
		   ttlMap = malloc((UCHAR_MAX+1) * sizeof(unsigned long *));
		   if(ttlMap == NULL) {
		        fprintf(stderr, "ERROR: initializing ttlMap, disabled\n");
			ttlMap = 0; 
                   } else {
		        memset(ttlMap, 0, ((UCHAR_MAX+1) * sizeof(unsigned long *)));
                   }
		   break;

              case 's': // source map
		   srcFlag++;
		   srcMap = malloc((USHRT_MAX + 1) * sizeof(unsigned long *));
		   if(srcMap == NULL) {
		        fprintf(stderr, "ERROR: initializing srcMap, disabled\n");
			srcMap = 0; 
                   } else {
		        memset(srcMap, 0, ((USHRT_MAX + 1) * sizeof(unsigned long *)));
                   }
		   break;

              case 'd': // dest map
		   dstFlag++;
		   dstMap = malloc((USHRT_MAX + 1) * sizeof(unsigned long *));
		   if(dstMap == NULL) {
		        fprintf(stderr, "ERROR: initializing dstMap, disabled\n");
			dstMap = 0; 
                   } else {
		        memset(dstMap, 0, ((USHRT_MAX + 1) * sizeof(unsigned long *)));
                   }
		   break;


            } // end switch
         } else { // argv[i][0] != '-'
                fileCount++;
	        fprintf(stderr, "INFO: opening %s\n", argv[i]); 
	        /* Open the capture file */
	    	if ( (fp= pcap_open_offline( argv[i], errbuf)) == NULL) {
	        	fprintf(stderr,"ERROR: %s %s.\n", argv[i], errbuf);
	        	return -1;
	    	}
	        // if a filter is specified apply it
	        if(use_filter==1) {
		    if(pcap_setfilter(fp, &bpf_f)) {
	                fprintf(stderr, "ERROR: applying filter: packet %ld %s\n", pkt_count, pcap_geterr(fp));
	            }	
	        }
	    	// read and dispatch packets until EOF is reached, or an error occurred
	    	if(pcap_loop(fp, 0, dispatcher_handler, argv[i]) == -1) {
	              fprintf(stderr, "ERROR: pcap_loop : packet %ld %s\n", pkt_count, pcap_geterr(fp));
	        }
	    	pcap_close(fp); 
        } 
    } // end for loop

    if(use_filter) {
        fprintf(stdout, "## Filter : %s\n", filter);
    }

    mapping_print();     // print the record details
    mapping_free();     // free the memory

    // if we counted TTL's report them to	
    if(ttlFlag) {
         int j;
         fprintf(stdout, "#TTLMAP:");
         for(j=0;j<UCHAR_MAX+1;j++) {
             	fprintf(stdout, " %lu", ttlMap[j]);
         }
         fprintf(stdout, "\n");
         free(ttlMap);
         ttlMap = NULL;
    }

    // if we counted SRC ports's report them to	
    if(srcFlag) {
         long j;
         fprintf(stdout, "#SRCMAP:");
         for(j=0;j<=USHRT_MAX;j++) {
            if(srcMap[j]>0) fprintf(stdout, " %lu,%lu", j, srcMap[j]);
         }
         fprintf(stdout, "\n");
         free(srcMap);
         srcMap = NULL;
    }

    // if we counted DST ports's report them to	
    if(dstFlag) {
         long j;
         fprintf(stdout, "#DSTMAP:");
         for(j=0;j<=USHRT_MAX;j++) {
            if(dstMap[j]>0) fprintf(stdout, " %lu,%lu", j, dstMap[j]);
         }
         free(dstMap);
         dstMap = NULL;
    }

    fprintf(stderr,"INFO: %s readed packets %lu\n", fileCount > 1 ? "" : argv[i-1], pkt_count);
    fprintf(stderr,"INFO: %s total wire data %lu\n",  fileCount > 1 ? "" : argv[i-1], data_count);
    fprintf(stderr,"INFO: %s total unique hosts %lu\n",  fileCount > 1 ? "" : argv[i-1], host_count);
    if(use_filter == 1) {
       pcap_freecode(&bpf_f);
    }

getrusage(RUSAGE_SELF, &musage);
fprintf(stderr, "INFO: %s mem usage %ld Kbytes\n", argv[i - 1], 
#ifdef __APPLE__ 
   musage.ru_maxrss/1024
#else
   musage.ru_maxrss
#endif
); 
    return 0;
}


void usage(char *v)
{
  fprintf(stderr, "INFO: %s Version %s\n", v, DUMP_VERSION);
  fprintf(stderr, "INFO: Using %s\n", pcap_lib_version() );
//  fprintf(stderr, "USAGE: %s filename(s) -> files to process, if filename is - then use STDIN\n", v);
  fprintf(stderr, "USAGE: %s filename(s) -> files to process\n", v);
  fprintf(stderr, "USAGE: %s -f \"BPF filter\" filename(s) -> Supply a BPF filter and cap file's to process\n", v);
  fprintf(stderr, "USAGE: %s -h (this help)\n", v);
  fprintf(stderr, "USAGE: %s -t ttl map, dumps a table with the counts of each ttl seen\n", v);
  fprintf(stderr, "USAGE: %s -s src tcp port count\n", v);
  fprintf(stderr, "USAGE: %s -d dst tcp port count\n", v);
  fprintf(stderr, "USAGE: Header explained:\n");
  fprintf(stderr, "#IP SNDPCKT RCVPCKT TCP UDP ICMP SNDATA RCVDATA [SRCTTL] FIRST_D FIRST_T LAST_D LAST_T [IP] [ID]\n");
  fprintf(stderr, "#IP          The IP address seen\n");
  fprintf(stderr, "#SNDPCKT     Number of packets where IP was the source\n");
  fprintf(stderr, "#RCVPCKT     Number of packets where IP was the destination\n");
  fprintf(stderr, "#TCP         Total number of TCP packets (src+dest)\n");
  fprintf(stderr, "#UDP         Total number of UDP packets (src_dest)\n");
  fprintf(stderr, "#ICMP        Total number of ICMP packets (src+dest)\n");
  fprintf(stderr, "#SNDDATA     Number of bytes (including headers) where IP is the source\n");
  fprintf(stderr, "#RCVDATA     Number of bytes (including headers) where IP is the destination\n");
  fprintf(stderr, "#[SRCTTL]    The TTL of last packet processed for this IP as source\n");
  fprintf(stderr, "#FIRST_D     GMT date of the earliest packet seen for this source IP\n");
  fprintf(stderr, "#FIRST_T     GMT time of the earliest packet seen for this source IP\n");
  fprintf(stderr, "#LAST_D      GMT date of the last packet seen for this IP\n");
  fprintf(stderr, "#LAST_T      GMT time of the last packet seen for this IP\n");
  fprintf(stderr, "#[IP]        The dest IP address of the last packet processed for this source IP\n");
  fprintf(stderr, "#[ID]        The ID field of the last packet processed for this source IP\n");
}





//// ==========================================================================================
// the single packet processing function, the magic
//// ==========================================================================================
void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct ether_header *eth;
    struct ip *iph;
    struct tcphdr *tcph;
    unsigned int  type;
    sHost *h;


    u_int i=0;
    pkt_count++;

    if(header->caplen < (ETHER_HDR_LEN + IP_HDR_LEN)) {
        fprintf(stderr, "%s INFO: packet %ld to small\n", temp1, pkt_count);
        return;
    }

    eth = (struct ether_header *)pkt_data;
    iph = (struct ip *)(pkt_data + ETHER_HDR_LEN); 
    type = ntohs(eth->ether_type);
    if(type == ETHERTYPE_VLAN) {
          type = ntohs(iph->ip_len);  // hack!!!!
          iph = (struct ip *)(pkt_data + ETHER_HDR_LEN + VLAN_TAG_LEN); 
    }

    if(type != ETHERTYPE_IP) {
          return;
    }

    if(iph->ip_v != IPVERSION) {
          fprintf(stderr, "%s INFO: packet %ld not IP v4 but 0x%02X\n", temp1, pkt_count, iph->ip_v);
          return;
    }

// it's ip v4 so the ports are just after this
    if(ttlFlag) {
           ttlMap[iph->ip_ttl]++;
    }

    data_count += header->len;
    // first we do the source we capture more
    h =  mapping_get_host((unsigned long)iph->ip_src.s_addr);
    if(h != NULL) {  			// we got the host structure
          h->last_host = iph->ip_dst;	// just store the dst host, in the report it will shown
          h->ttl= iph->ip_ttl;		// just store the ttl, this will be reported  
          h->id= iph->ip_id;		// just store the id, this will be reported  
          h->snd_packets++;		//
          h->snd_data += header->len;	//
          switch(iph->ip_p) {		// count the protocol 
                default:
			h->unknown++;
			break;
                case IPPROTO_TCP:
                        if(srcFlag && header->caplen > (ETHER_HDR_LEN + IP_HDR_LEN + 10) ) {
			   // should calc proper ip hdr len
                           tcph = (struct tcphdr *)((unsigned char *)iph + IP_HDR_LEN);
                           srcMap[ntohs(tcph->source)]++;
                        }
			h->tcp++;
                        break;
                case IPPROTO_UDP:
			h->udp++;
                        break;
                case IPPROTO_ICMP:
			h->icmp++;
                        break;
          }
	  // store/update time stamps
          // don't assume they are in sequence
	  if(h->first.tv_usec == 0) {
                h->first = header->ts;
//                              h->last = header->ts;
          } else {
                if(header->ts.tv_sec >= h->last.tv_sec) {
                       if(header->ts.tv_sec == h->last.tv_sec) {
	      	            if(header->ts.tv_usec > h->last.tv_usec) 
                                   h->last = header->ts;
                       } else {
                            h->last = header->ts;
                       }
                } else { 
                       if(header->ts.tv_sec <= h->first.tv_sec) {
                           if(header->ts.tv_sec == h->first.tv_sec) {
                                if(header->ts.tv_usec < h->first.tv_usec) h->first = header->ts;
                           } else {
                                h->first = header->ts;
                           }
                       } 
                }
          }
    } // end h != NULL

    // do some counting for the dst ip... 
    h =  mapping_get_host((unsigned long)iph->ip_dst.s_addr);
    if(h != NULL) {
          h->last_host = iph->ip_src;
          h->rcv_packets++;
          h->rcv_data += header->len;
          switch(iph->ip_p) {
                  default:
		       h->unknown++;
                       break;
                  case IPPROTO_TCP:
                        if(dstFlag && header->caplen > (ETHER_HDR_LEN + IP_HDR_LEN + 10) ) {
			   // should calc proper ip hdr len
                           tcph = (struct tcphdr *)((unsigned char *)iph + IP_HDR_LEN);
                           dstMap[ntohs(tcph->dest)]++;
                        }
		       h->tcp++;
                       break;
                  case IPPROTO_UDP:
                       h->udp++;
                       break;
                  case IPPROTO_ICMP:
                       h->icmp++;
                       break;
          }
	// store/update time stamps don't assume they are in sequence
        // here something strange might happen... 
        // if there are only packets for this host as destination and the host
        // never sends data the first_seen stucture will stay 0 as first_seen
        // is only set for the sending host/ip
        if(header->ts.tv_sec >= h->last.tv_sec) {
             if(header->ts.tv_sec == h->last.tv_sec) {
                    if (header->ts.tv_usec > h->last.tv_usec) 
                              h->last = header->ts; 
             } else { 
                    h->last = header->ts;
             }
        } else {
             if(header->ts.tv_sec <= h->first.tv_sec) {
                   if(header->ts.tv_sec == h->first.tv_sec) {
                              if (header->ts.tv_usec < h->first.tv_usec) 
                                        h->first = header->ts;
                   } else {
                              h->first = header->ts;
                   }
             }
        }
    } // end h != NULL
    return;
    // Print the packet */
    for (i=0;i<header->caplen;i++) {
        if((i % 32) == 0) fprintf(stderr, "\n");
        fprintf(stderr, "%02X ", pkt_data[i]);
    }
    fprintf(stderr, "\n");
}



//// ==========================================================================================
// walk the table created and free the memory 
// at the end the table should zero size
//// ==========================================================================================
int mapping_free(void)
{
int idx0, idx1, idx2, idx3;
sHost *sH;

for(idx0 = 0; idx0 < 256; idx0++) {
  if(root[idx0] != NULL) {
    for(idx1=0;idx1 < 256; idx1++) {
       if(root[idx0][idx1] != NULL) {
         for(idx2=0;idx2 < 256 ; idx2++) {
            if(root[idx0][idx1][idx2] != NULL) {
              for(idx3=0;idx3<256;idx3++) {
                 if(root[idx0][idx1][idx2][idx3] != NULL) {
                     free(root[idx0][idx1][idx2][idx3]);
                 } // if idx3
              } // for idx3
             free(root[idx0][idx1][idx2]);
            } // if idx2
         } // for idx2
         free(root[idx0][idx1]);
       } // if idx1
    } // for idx1
    free(root[idx0]);
  } // if idx0
} // for idx0
free(root);
root = NULL;
return 0;
}




//// ==========================================================================================
// walk the table created if there is a 'record' print it 
//// ==========================================================================================
int mapping_print(void)
{
int idx0, idx1, idx2, idx3;
sHost *sH;
host_count = 0;

for(idx0 = 0; idx0 < 256; idx0++) {
  if(root[idx0] != NULL) {
    for(idx1=0;idx1 < 256; idx1++) {
       if(root[idx0][idx1] != NULL) {
         for(idx2=0;idx2 < 256 ; idx2++) {
            if(root[idx0][idx1][idx2] != NULL) {
              for(idx3=0;idx3<256;idx3++) {
                 if(root[idx0][idx1][idx2][idx3] != NULL) {
                     sH = (sHost *)(root[idx0][idx1][idx2][idx3]);
                     host_count++;
                     mapping_print_record(idx0,idx1,idx2,idx3,(sHost *)sH);
                 } // if idx3
              } // for idx3
            } // if idx2
         } // for idx2
       } // if idx1
    } // for idx1
  } // if idx0
} // for idx0
return 0;
}


//// ==========================================================================================
//   Just dump the entry, print a header if not done already
//// ==========================================================================================
int mapping_print_record(u_char idx0, u_char idx1, u_char idx2, u_char idx3, sHost *h)
{
struct tm *f, *l;

 if(!header_printed) {
  printf("#IP SNDPCKT RCVPCKT TCP UDP ICMP SNDATA RCVDATA SNDTTL FIRST_D FIRST_T LAST_D LAST_T [LASTIP] [LASTID]\n");
  header_printed++;
 }
 printf("%d.%d.%d.%d %ld %ld %ld %ld %ld %ld %ld ", idx0,idx1,idx2,idx3, h->snd_packets, h->rcv_packets, h->tcp, h->udp, h->icmp, h->snd_data, h->rcv_data);
 if(h->ttl > 0) printf("%d ", h->ttl); else printf("- ");
 if(h->first.tv_sec > 0) {
  f = localtime(&h->first.tv_sec);
  printf("%04d%02d%02d %02d:%02d:%02d.%lu ", (1900 + f->tm_year), (1+ f->tm_mon), f->tm_mday, f->tm_hour, f->tm_min, f->tm_sec, h->first.tv_usec);
 } else printf("- - ");
 l = localtime(&h->last.tv_sec);
 printf("%04d%02d%02d %02d:%02d:%02d.%lu ", (1900 + l->tm_year), (1+ l->tm_mon), l->tm_mday, l->tm_hour, l->tm_min, l->tm_sec, h->last.tv_usec); 
 printf("%s ", inet_ntoa(h->last_host));
 if(h->id > 0) printf("%u ", h->id); else printf("- ");
 printf("\n");
}


//// ==========================================================================================
// init the root stucture
//// ==========================================================================================
int mapping_init(void)
{
 if(root == NULL) {
  root = malloc(256 * sizeof(unsigned long *));
  if(root == NULL) {
    fprintf(stderr, "No mem for Root\n");
    return -1;
  }
  memset(root, 0, (256 * sizeof(unsigned long *)));
 }
 return 0;
}


//// ==========================================================================================
// find the entry for the specific ip adress, if it's not there create the entry
//// ==========================================================================================
sHost *mapping_get_host(unsigned long val)
{
char *ip = (char *)&val;
int i ;
unsigned char idx0, idx1, idx2, idx3;
sHost *sH;

 idx0 = (0xFF & ip[0]);
 idx1 = (0xFF & ip[1]);
 idx2 = (0xFF & ip[2]);
 idx3 = (0xFF & ip[3]);


 if(root[idx0] == NULL) {
    root[idx0] = malloc(256 * sizeof(unsigned long *)) ;
    if(root[idx0] == NULL) { 
       fprintf(stderr, "index %d/0x%02X no mem\n", 0, idx0);
       return NULL;
    } 
    memset(root[idx0], 0, (256 * sizeof(unsigned long *)));
 } 
 
 if(root[idx0][idx1] == NULL) {
    root[idx0][idx1] = malloc(256 * sizeof(unsigned long *)) ;
    if(root[idx0][idx1] == NULL) { 
       fprintf(stderr, "index %d/0x%02X no mem\n", 1, idx1);
       return NULL;
    } 
    memset(root[idx0][idx1], 0, (256 * sizeof(unsigned long *)));
 } 

 if(root[idx0][idx1][idx2] == NULL) {
    root[idx0][idx1][idx2] = malloc(256 * sizeof(unsigned long *)) ;
    if(root[idx0][idx1][idx2] == NULL) { 
       fprintf(stderr, "index %d/0x%02X no mem\n", 2, idx2);
       return NULL;
    } 
    memset(root[idx0][idx1][idx2], 0, (256 * sizeof(unsigned long *)));
 } 

 if(root[idx0][idx1][idx2][idx3] == NULL) {
    root[idx0][idx1][idx2][idx3] = malloc(sizeof(sHost)) ;
    if(root[idx0][idx1][idx2][idx3] == NULL) { 
       fprintf(stderr, "index %d/0x%02X no mem\n", 3, idx3);
       return NULL;
    } 
    memset((root[idx0][idx1][idx2][idx3]), 0, sizeof(sHost));
 } 
 return (sHost *)root[idx0][idx1][idx2][idx3];
 }

