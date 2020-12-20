#include "peer_packet.h"

#include <malloc.h>
#include <string.h>

whohas_packet* create_whohas_pkt(list *chunks_to_download) {
    whohas_packet* pkt = (whohas_packet *)(malloc(sizeof(whohas_packet)));
    pkt->header.magicnum = MAGIC;
    pkt->header.version = VERSION;
    pkt->header.packet_type = WHOHAS;
    pkt->header.header_len = sizeof(packet_header);
    pkt->header.packet_len = sizeof(whohas_packet);
    pkt->header.seq_num = INVALID_SEQ;
    pkt->header.ack_num = INVALID_ACK;
    
    int size = list_size(chunks_to_download);
    
    // if number of chunk hashs of the file is too large (> 50)
    // then splite to several whohas packet
    // if(size > CHUNKHASHS_MAX_NUM) { ... }
    pkt->chunkhashs_num = size;

    chunk *chunk_p;
    for(int i = 0; i < size; i++) {
        chunk_p = (chunk *)list_get(chunks_to_download, i);
        char *sha1 = chunk_p->sha1; // hex string of sha1
        uint8_t sha1_binary[CHUNKHASHS_SIZE]; // binary sha1
        hex2binary(sha1, CHUNKHASHS_HEX_SIZE, sha1_binary); 
        memcpy((pkt->chunkhashs) + (i * CHUNKHASHS_SIZE), sha1_binary, CHUNKHASHS_SIZE);
    }

    // adjust total packet length according to chunk hashs' number
    pkt->header.packet_len = sizeof(packet_header) + 4 + size * CHUNKHASHS_SIZE;

    convert(pkt, NETWORK);

    return pkt;
}

ihave_packet* create_ihave_pkt(list *chunks_i_have) {
    ihave_packet* pkt = (ihave_packet *)(malloc(sizeof(ihave_packet)));
    pkt->header.magicnum = MAGIC;
    pkt->header.version = VERSION;
    pkt->header.packet_type = IHAVE;
    pkt->header.header_len = sizeof(packet_header);
    pkt->header.packet_len = sizeof(ihave_packet);
    pkt->header.seq_num = INVALID_SEQ;
    pkt->header.ack_num = INVALID_ACK;
    
    int size = list_size(chunks_i_have);
    pkt->chunkhashs_num = size;

    chunk *chunk_p;
    for(int i = 0; i < size; i++) {
        chunk_p = (chunk *)list_get(chunks_i_have, i);
        char *sha1 = chunk_p->sha1; // hex string of sha1
        uint8_t sha1_binary[CHUNKHASHS_SIZE]; // binary sha1
        hex2binary(sha1, CHUNKHASHS_HEX_SIZE, sha1_binary); 
        memcpy((pkt->chunkhashs) + (i * CHUNKHASHS_SIZE), sha1_binary, CHUNKHASHS_SIZE);
    }

    // adjust total packet length according to chunk hashs' number
    pkt->header.packet_len = sizeof(packet_header) + 4 + size * CHUNKHASHS_SIZE;

    convert(pkt, NETWORK);

    return pkt;
}

get_packet* create_get_pkt(uint8_t *chunk_hash) {
    get_packet* pkt = (get_packet *)(malloc(sizeof(get_packet)));
    pkt->header.magicnum = MAGIC;
    pkt->header.version = VERSION;
    pkt->header.packet_type = GET;
    pkt->header.header_len = sizeof(packet_header);
    pkt->header.packet_len = sizeof(get_packet);
    pkt->header.seq_num = INVALID_SEQ;
    pkt->header.ack_num = INVALID_ACK;

    memcpy(pkt->chunk_to_fetch, chunk_hash, CHUNKHASHS_SIZE);

    convert(pkt, NETWORK);

    return pkt;
}

data_packet* create_data_pkt(uint8_t *data, u_int seq) {
    data_packet* pkt = (data_packet *)(malloc(sizeof(data_packet)));
    pkt->header.magicnum = MAGIC;
    pkt->header.version = VERSION;
    pkt->header.packet_type = DATA;
    pkt->header.header_len = sizeof(packet_header);
    pkt->header.packet_len = sizeof(data_packet);
    pkt->header.seq_num = seq;
    pkt->header.ack_num = INVALID_ACK;

    memcpy(pkt->chunk_data, data, PACKET_MAX_DATA_SIZE);

    // IN THIS PROJECT, every DATA packet I SEND contains 1kb data
    // thus i need to adjust total packet length
    pkt->header.packet_len = sizeof(packet_header) + PACKET_MAX_DATA_SIZE;

    convert(pkt, NETWORK);

    return pkt;
}

ack_packet* create_ack_pkt(u_int ack) {
    ack_packet* pkt = (ack_packet *)(malloc(sizeof(ack_packet)));
    pkt->header.magicnum = MAGIC;
    pkt->header.version = VERSION;
    pkt->header.packet_type = ACK;
    pkt->header.header_len = sizeof(packet_header);
    pkt->header.packet_len = sizeof(ack_packet);
    pkt->header.seq_num = INVALID_SEQ;
    pkt->header.ack_num = ack;

    convert(pkt, NETWORK);

    return pkt;
}

void convert(void *pkt, send_to side) {
    packet_header *header = (packet_header *)pkt;
    switch (side) {
        case HOST:
            header->magicnum = ntohs(header->magicnum);
            header->header_len = ntohs(header->header_len);
            header->packet_len = ntohs(header->packet_len);
            header->seq_num = ntohl(header->seq_num);
            header->ack_num = ntohl(header->ack_num);
            break;
        case NETWORK:
            header->magicnum = htons(header->magicnum);
            header->header_len = htons(header->header_len);
            header->packet_len = htons(header->packet_len);
            header->seq_num = htonl(header->seq_num);
            header->ack_num = htonl(header->ack_num);
            break;
        default:
            break;
    }
}
