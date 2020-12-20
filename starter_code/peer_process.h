#ifndef _PEER_PROCESS_H_
#define _PEER_PROCESS_H_

#include "peer_packet.h"
#include "peer_chunk.h"
#include "peer_list.h"
#include "bt_parse.h"
#include "spiffy.h"

void process_download(char *chunkfile, char *outputfile);

void process_WHOHAS(whohas_packet *pkt, bt_peer_t *source_peer);

void process_IHAVE(ihave_packet *pkt, bt_peer_t *source_peer);

void process_timeout();

void process_GET(get_packet *pkt, bt_peer_t *source_peer);

void process_DATA(data_packet *pkt, bt_peer_t *source_peer);

void process_ACK(ack_packet *pkt, bt_peer_t *source_peer);

void process_DENIED();

#endif
