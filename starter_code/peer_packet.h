#ifndef _PEER_PACKET_H_
#define _PEER_PACKET_H_

#include "peer_list.h"
#include "peer_chunk.h"

#include <sys/types.h>
#include <netinet/in.h>

#define PACKET_MAX_SIZE 1500
#define PACKET_MAX_DATA_SIZE 1024 // 1kb
#define CHUNKHASHS_SIZE 20
#define CHUNKHASHS_HEX_SIZE ((2 * CHUNKHASHS_SIZE) + 1)
#define CHUNKHASHS_MAX_NUM 50
#define CHUNKDATA_SIZE 512

#define MAGIC 15441
#define VERSION 1
#define INVALID_SEQ 0
#define INIT_SEQ 1
#define INVALID_ACK 0
#define INIT_ACK 1

typedef enum packet_type {
    WHOHAS, IHAVE, GET, DATA, ACK, DENIED
} packet_type;

typedef enum send_to {
    HOST, NETWORK
} send_to;

typedef struct packet_header {
  short magicnum;
  char version;
  char packet_type;
  short header_len;
  short packet_len; 
  u_int seq_num;
  u_int ack_num;
} packet_header;


typedef struct whohas_packet {
    packet_header header;
    char chunkhashs_num;
    char padding[3];
    uint8_t chunkhashs[(CHUNKHASHS_SIZE * CHUNKHASHS_MAX_NUM)];
} whohas_packet;

typedef struct ihave_packet {
    packet_header header;
    char chunkhashs_num;
    char padding[3];
    uint8_t chunkhashs[(CHUNKHASHS_SIZE * CHUNKHASHS_MAX_NUM)];
} ihave_packet;


typedef struct get_packet {
    packet_header header;
    uint8_t chunk_to_fetch[CHUNKHASHS_SIZE];
} get_packet;


typedef struct data_packet {
    packet_header header;
    uint8_t chunk_data[PACKET_MAX_SIZE - sizeof(packet_header)];
} data_packet;

typedef struct ack_packet {
    packet_header header;
} ack_packet;


whohas_packet* create_whohas_pkt(list *chunks_to_download);

ihave_packet* create_ihave_pkt(list *chunks_i_have);

get_packet* create_get_pkt(uint8_t *chunk_hash);

data_packet* create_data_pkt(uint8_t *data, u_int seq);

ack_packet* create_ack_pkt(u_int ack);

void convert(void *pkt, send_to side);

#endif
