#include "peer_function.h"
#include <malloc.h>

extern bt_config_t config;
extern int sock;

extern list *peers_GET_pkt_sent;
extern list *chunks_to_send;

void send_packet(bt_peer_t *peer, void *pkt, int pkt_size) {
    spiffy_sendto(sock, pkt, pkt_size, 0, (struct sockaddr *)&(peer->addr), sizeof(&(peer->addr)));
}

bt_peer_t* get_peer_by_id(short peer_id) {
    bt_peer_t *peer;
    for (peer = config.peers; peer != NULL; peer = peer->next) {
        if (peer->id == peer_id) {
            return peer;
        }
    }
    return NULL;
}

void send_GET_pkt(chunk* ck) {
    // choose an owner peer as target peer to send GET packet
    list *owners = ck->owner_peers_id;
    short *target_peer_id = (short *)(malloc(sizeof(short)));
    bt_peer_t *target_peer;
    if (peers_GET_pkt_sent == NULL) {
        peers_GET_pkt_sent = list_init();
    }

    int available_peer_found = 0;
    for (int p = 0; p < owners->size; p++) {
        *target_peer_id = *((short *)(list_get(owners, p)));
        target_peer = get_peer_by_id(*target_peer_id);
        if(!target_peer) {
            printf("WARNING: TARGET PEER NOT FOUND: %d\n", *target_peer_id);
            chunk_remove_owner(ck, *target_peer_id);
            free(target_peer_id);
            p--;
            continue ;
        }
            
        // check if this peer is downloading from target peer
        int target_peer_available = 1;
        int size = peers_GET_pkt_sent->size;
        for (int i = 0; i < size; i++) {
            short peer_id = *((short *)(list_get(peers_GET_pkt_sent, i)));
            if (peer_id == *target_peer_id) {
                // if so, find next owner peer
                target_peer_available = 0;
                break;
            }
        }
        // if not, use this peer
        if (target_peer_available) {
            available_peer_found = 1;
            break;
        }
    }

    if (!available_peer_found) {
        return ;
    }

    // create GET packet
    uint8_t hash_binary[CHUNKHASHS_SIZE];
    hex2binary(ck->sha1, CHUNKHASHS_HEX_SIZE, hash_binary);
    get_packet* pkt = create_get_pkt(hash_binary);

    // send GET packet
    send_packet(target_peer, pkt, pkt->header.packet_len);

    // add this peer to peers_GET_pkt_sent
    if (peers_GET_pkt_sent == NULL) {
        peers_GET_pkt_sent = list_init();
    }
    list_add(peers_GET_pkt_sent, peers_GET_pkt_sent->size, target_peer_id);

    // change the state of this chunk
    ck->state = DOWNLOADING;
    ck->from_or_to_id = *target_peer_id;

    // free GET pkt
    free(pkt);
}

void send_DATA_pkt() {
    // send DATA packet for a chunk
    if (chunks_to_send == NULL || chunks_to_send->size == 0) {
        return;
    }

    int size = chunks_to_send->size;
    chunk *ck;
    bt_peer_t *target_peer;
    int i;
    for (i = 0; i < size; i++) {
        ck = (chunk *)(list_get(chunks_to_send, i));
        if ((target_peer = get_peer_by_id(ck->from_or_to_id)) != NULL) {
            break;
        } else {
            list_remove(chunks_to_send, i);
            i--;
        }
    }

    if (target_peer) {
        window *ww = ck->window;
        for (int j = 0; j < WINDOW_SIZE; j++) {
            int next_index = ww->base_index + j * PACKET_MAX_DATA_SIZE;
            if((ww->wd[j] == 0 || ww->wd[j] == 1) && next_index < BT_CHUNK_SIZE) {
                u_int seq = (next_index / PACKET_MAX_DATA_SIZE) + 1;
                data_packet* pkt = create_data_pkt(ck->data + next_index, seq);
                send_packet(target_peer, pkt, pkt->header.packet_len);
                free(pkt);
                ww->wd[j] = 1;
            }
        }
    }
}
