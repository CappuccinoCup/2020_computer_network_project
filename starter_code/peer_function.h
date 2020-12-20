#ifndef _PEER_FUNCTION_H_
#define _PEER_FUNCTION_H_

#include "peer_chunk.h"
#include "peer_list.h"
#include "peer_packet.h"
#include "bt_parse.h"
#include "spiffy.h"
#include <stdio.h>

void send_packet(bt_peer_t *peer, void *pkt, int pkt_size);

bt_peer_t* get_peer_by_id(short peer_id);

void send_GET_pkt(chunk* ck);

void send_DATA_pkt();

#endif