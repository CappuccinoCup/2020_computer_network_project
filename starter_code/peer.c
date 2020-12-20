/*
 * peer.c
 * 
 * Author: Yi Lu <19212010040@fudan.edu.cn>,
 *
 * Modified from CMU 15-441,
 * Original Authors: Ed Bardsley <ebardsle+441@andrew.cmu.edu>,
 *                   Dave Andersen
 * 
 * Class: Networks (Spring 2015)
 * 
 * 
 * Finisher: Liang Chaoyi <18302010035@fudan.edu.cn>
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"

#include "peer_process.h"
#include "peer_packet.h"

bt_config_t config;
int sock;

void peer_run(bt_config_t *config);


int main(int argc, char **argv) {
  bt_init(&config, argc, argv);

  DPRINTF(DEBUG_INIT, "peer.c main beginning\n");

#ifdef TESTING
  config.identity = 1; // your group number here
  strcpy(config.chunk_file, "chunkfile");
  strcpy(config.has_chunk_file, "haschunks");
#endif

  bt_parse_command_line(&config);

#ifdef DEBUG
  if (debug & DEBUG_INIT) {
    bt_dump_config(&config);
  }
#endif
  
  peer_run(&config);
  return 0;
}

void process_inbound_udp(int sock) {
  #define BUFLEN 1500
  struct sockaddr_in from;
  socklen_t fromlen;
  char buf[BUFLEN];
  
  fromlen = sizeof(from);
  spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen);

  // look for which peer this packet from, get the source peer
  bt_peer_t *source_peer;
  int source_peer_found = 0;
  for (source_peer = config.peers; source_peer != NULL; source_peer = source_peer->next) {
      if (source_peer->addr.sin_port == from.sin_port) {
        source_peer_found = 1;
        break;
      }
  }

  if(source_peer_found != 1) {
    printf("WARNING: UDP FROM UNKNOWN PEER RECEIVED\n");
    return ;
  }

  convert(buf, HOST);

  packet_header *pkt_p = (packet_header *)buf;
  char pkt_type = pkt_p->packet_type;

  printf("NEW PACKET FROM (%s:%d)  TYPE: %d\n", 
    inet_ntoa(from.sin_addr), ntohs(from.sin_port), pkt_type);

  switch (pkt_type)
  {
  case WHOHAS:
    process_WHOHAS((whohas_packet *)buf, source_peer);
    break;

  case IHAVE:
    process_IHAVE((ihave_packet *)buf, source_peer);
    break;

  case GET:
    process_GET((get_packet *)buf, source_peer);
    break;

  case DATA:
    process_DATA((data_packet *)buf, source_peer);
    break;

  case ACK:
    process_ACK((ack_packet *)buf, source_peer);
    break;

  case DENIED:
    process_DENIED();
    break;
  
  default:
    break;
  }
}

void process_get(char *chunkfile, char *outputfile) {
  // usage: GET <get-chunk-file> <output filename>
  // e.g. GET /tmp/B.chunks /tmp/newB.tar
  printf("REQUEST FROM USER: (%s, %s)\n", 
	  chunkfile, outputfile);

  process_download(chunkfile, outputfile);
}

void handle_user_input(char *line, void *cbdata) {
  char chunkf[128], outf[128];

  bzero(chunkf, sizeof(chunkf));
  bzero(outf, sizeof(outf));

  if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
    if (strlen(outf) > 0) {
      process_get(chunkf, outf);
    }
  }
}


void peer_run(bt_config_t *config) {
  struct sockaddr_in myaddr;
  fd_set readfds;
  struct user_iobuf *userbuf;
  
  if ((userbuf = create_userbuf()) == NULL) {
    perror("peer_run could not allocate userbuf");
    exit(-1);
  }
  
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
    perror("peer_run could not create socket");
    exit(-1);
  }
  
  bzero(&myaddr, sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  myaddr.sin_port = htons(config->myport);
  
  if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
    perror("peer_run could not bind socket");
    exit(-1);
  }
  
  spiffy_init(config->identity, (struct sockaddr *)&myaddr, sizeof(myaddr));
  
  while (1) {
    int nfds;
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sock, &readfds);
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 500000; // 0.5s
    
    nfds = select(sock+1, &readfds, NULL, NULL, &timeout);
    
    if (nfds > 0) {
      if (FD_ISSET(sock, &readfds)) {
	      process_inbound_udp(sock);
      }
      
      if (FD_ISSET(STDIN_FILENO, &readfds)) {
	      process_user_input(STDIN_FILENO, userbuf, handle_user_input,
			   "Currently unused");
      }
    } else if (nfds == 0) {
      // if time out, check if this peer is downloading file
      // if so, resend GET packets and DATA packets
      process_timeout();
    }
  }
}
