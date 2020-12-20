#include "peer_process.h"

#include <stdio.h>
#include <string.h>
#include <malloc.h>

#define LINE_LEN 100
#define FILENAME_LEN 255


extern bt_config_t config;
extern int sock;

int downloading;
char chunk_file[FILENAME_LEN];
char output_file[FILENAME_LEN];
list *chunks_to_download;   // all chunks this peer needs to download
list *peers_GET_pkt_sent;   // all peers this peer has sent GET packet to

list *chunks_to_send;       // all chunks this peer needs to send

int complete_download() {
    FILE *fp;
    if ((fp = fopen(output_file, "w+")) == NULL) {
        printf("ERROR: FILE %s CREATE FAILED\n", output_file);
        return 0;
    }

    // assemble all chunks and save file
    int size = list_size(chunks_to_download);
    chunk *chunk_p;
    for(int i = 0; i < size; i++) {
        chunk_p = (chunk *)list_get(chunks_to_download, i);
        fseek(fp, chunk_p->id * BT_CHUNK_SIZE, SEEK_SET);
        fwrite(chunk_p->data, BT_CHUNK_SIZE, 1, fp);
    }

    // close file
    fclose(fp);

    // release chunks in list
    for(int i = 0; i < size; i++) {
        chunk_p = (chunk *)list_remove(chunks_to_download, 0);
        chunk_clean(chunk_p);
    }

    // release list
    list_clean(chunks_to_download);

    printf("GOT %s\n", chunk_file);
    downloading = 0;
    return 1;
}

void process_download(char *chunkfile, char *outputfile) {
    // reject concurrent file download requests from user
    if(downloading) {
        printf("LAST TASK IS DOWNLOADING...\n");
        return ;
    } else {
        downloading = 1;
    }

    strcpy(chunk_file, chunkfile);
    strcpy(output_file, outputfile);

    // open chunkfile
    FILE *fp;
    if ((fp = fopen(chunk_file, "r")) == NULL) {
        printf("ERROR: FILE %s OPEM FAILED\n", chunk_file);
        return ;
    }
    
    // initailize list of chunks to download
    chunks_to_download = list_init();
    
    // read all chunk hashs into list
    char buf[LINE_LEN];
    while (!feof(fp) && (fgets(buf, LINE_LEN, fp) != NULL)) {
        chunk *new_chunk = chunk_init();
        sscanf(buf, "%d %s", &new_chunk->id, new_chunk->sha1);
        list_add(chunks_to_download, chunks_to_download->size, new_chunk);
    }

    // close file
    fclose(fp);

    // send WHOHAS packet to all peers
    whohas_packet *pkt = create_whohas_pkt(chunks_to_download);
    bt_peer_t *target_peer = config.peers;
    while (target_peer != NULL) {
        if (target_peer->id != config.identity) {
            send_packet(target_peer, pkt, pkt->header.packet_len);
        }
        target_peer = target_peer->next;
    }

    // release WHOHAS packet
    free(pkt);

    // next to do: 
    // wait for ihave packet, send get packet and then wait for data packet
    // every time receive a data packet, check if all chunks are downloaded
    // if so, assemble all chunks to a file, save the file, print a message
    // finally don't forget to release all resources: list and chunks in it
}

void process_timeout() {
    // if is downloading: 
    // send GET packet for each WAITING chunk to all peers
    // send ACK packet for each DOWNLOADING chunk to reliable peer;
    //      if RESEND ACK for too much times, give up this peer
    if (downloading) {
        int size = list_size(chunks_to_download);
        for (int i = 0; i < size; i++) {
            chunk* ck = (chunk *)(list_get(chunks_to_download, i));
            if (ck->state != FINISHED) {
                if (ck->state == DOWNLOADING) {
                    bt_peer_t *target_peer = get_peer_by_id(ck->from_or_to_id);
                    if(target_peer == NULL || ck->reconnect_time > 10) {
                        // give up this owner peer
                        ck->reconnect_time = 0;
                        chunk_remove_owner(ck, ck->from_or_to_id);
                        // change this chunks's state to WAITING
                        ck->state = WAITING;
                        ck->from_or_to_id = -1;
                        ck->window->base_index = 0;
                        ck->window->last_ack_num = 0;
                        for (int j = 0; j < WINDOW_SIZE; j++) {
                            ck->window->wd[j] = 0;
                        }
                    } else {
                        ck->reconnect_time++;
                    }
                }
                if (ck->state == WAITING) {
                    if (ck->owner_peers_id->size == 0) {
                        // send WHOHAS packet to all peers
                        list *l = list_init();
                        list_add(l, 0, ck->sha1);
                        whohas_packet *pkt = create_whohas_pkt(l);
                        bt_peer_t *target_peer = config.peers;
                        while (target_peer != NULL) {
                            if (target_peer->id != config.identity) {
                                send_packet(target_peer, pkt, pkt->header.packet_len);
                            }
                            target_peer = target_peer->next;
                        }
                        free(pkt);
                        list_clean(l);

                        printf("FOR %s\n", ck->sha1);
                        printf("RESEND WHOHAS...\n");

                    } else {
                        send_GET_pkt(ck);
                    }
                }
            }
        }
    }

    // if this peer is sending data, ckeck and resend
    send_DATA_pkt();
}

void process_WHOHAS(whohas_packet *pkt, bt_peer_t *source_peer) {
    // open has-chunk-file
    FILE *fp;
    if ((fp = fopen(config.has_chunk_file, "r")) == NULL) {
        printf("ERROR: FILE %s OPEM FAILED\n", config.has_chunk_file);
        return ;
    }
    
    // initailize list of chunks i have
    list *chunks_ihave = list_init();
    
    // read all chunk hashs into list
    char buf[LINE_LEN];
    while (!feof(fp) && (fgets(buf, LINE_LEN, fp) != NULL)) {
        chunk *new_chunk = chunk_init();
        sscanf(buf, "%d %s", &new_chunk->id, new_chunk->sha1);
        // append this new chunk
        list_add(chunks_ihave, chunks_ihave->size, new_chunk);
    }

    // close file
    fclose(fp);

    int have_size = list_size(chunks_ihave);
    chunk *chunk_p;

    // initialize list of chunks i can offer
    list *chunks_offer = list_init();

    // get chunk hashs in whohas packet
    int chunk_hashs_num = pkt->chunkhashs_num;
    char hash[CHUNKHASHS_HEX_SIZE];
    for(int i = 0; i < chunk_hashs_num; i++) {
        uint8_t *hash_binary = ((pkt->chunkhashs) + (i * CHUNKHASHS_SIZE));
        binary2hex(hash_binary, CHUNKHASHS_SIZE, hash);
        // search if hash is in chunks_ihave
        // if so, add this chunk's pointer to chunks_offer
        for (int j = 0; j < have_size; j++) {
            chunk_p = (chunk *)(list_get(chunks_ihave, j));
            if(memcmp(chunk_p->sha1, hash, CHUNKHASHS_HEX_SIZE) == 0) {
                list_add(chunks_offer, chunks_offer->size, chunk_p);
                break;
            }
        }
    }

    // if i don't have those chunks, return
    if (chunks_offer->size == 0) {
        return ;
    }

    // create IHAVE packet using chunks_offer list
    ihave_packet *ihave_pkt = create_ihave_pkt(chunks_offer);

    // send IHAVE packet to source peer
    send_packet(source_peer, ihave_pkt, pkt->header.packet_len);

    // release IHAVE packet
    free(ihave_pkt);

    // release chunks in list
    for(int i = 0; i < have_size; i++) {
        chunk_p = (chunk *)list_remove(chunks_ihave, 0);
        chunk_clean(chunk_p);
    }

    // release list
    list_clean(chunks_offer);
    list_clean(chunks_ihave);
}

void process_IHAVE(ihave_packet *pkt, bt_peer_t *source_peer) {
    // if not downloading, return
    if(!downloading) {
        return ;
    }

    int chunk_hashs_num = pkt->chunkhashs_num;  // how many chunk hashs in IHAVE packet
    char hash[CHUNKHASHS_HEX_SIZE];             // hex string of chunk hash
    int size = list_size(chunks_to_download);   // how many chunks in chunks_to_download list
    chunk *chunk_p;                             // a chunk pointer

    for(int i = 0; i < chunk_hashs_num; i++) {
        uint8_t *hash_binary = ((pkt->chunkhashs) + (i * CHUNKHASHS_SIZE));
        binary2hex(hash_binary, CHUNKHASHS_SIZE, hash);
        // search if this chunk's hash is in chunks_to_download
        // if so, add source_peer's id to this chunk's owner_peers_id list
        for (int j = 0; j < size; j++) {
            chunk_p = (chunk *)(list_get(chunks_to_download, j));
            if(memcmp(chunk_p->sha1, hash, CHUNKHASHS_HEX_SIZE) == 0) {
                list* owners = chunk_p->owner_peers_id;
                short *id = (short *)(malloc(sizeof(short)));
                *id = source_peer->id;
                list_add(owners, owners->size, id);
                break;
            }
        }
    }

    // send GET packets for each WAITING chunk in chunks_to_download
    for (int i = 0; i < size; i++) {
        chunk* ck = (chunk *)(list_get(chunks_to_download, i));
        if(ck->state == WAITING && ck->owner_peers_id->size != 0) {
            send_GET_pkt(ck);
        }
    }
}

void process_GET(get_packet *pkt, bt_peer_t *source_peer) {
    // open has-chunk-file
    FILE *fp;
    if ((fp = fopen(config.has_chunk_file, "r")) == NULL) {
        printf("ERROR: FILE %s OPEM FAILED\n", config.has_chunk_file);
        return ;
    }
    
    // initailize list of chunks i have
    list *chunks_ihave = list_init();
    
    // read all chunk hashs into list
    char buf[LINE_LEN];
    while (!feof(fp) && (fgets(buf, LINE_LEN, fp) != NULL)) {
        chunk *new_chunk = chunk_init();
        sscanf(buf, "%d %s", &new_chunk->id, new_chunk->sha1);
        // append this new chunk
        list_add(chunks_ihave, chunks_ihave->size, new_chunk);
    }

    // close file
    fclose(fp);

    // get chunk hash in GET packet
    char hash[CHUNKHASHS_HEX_SIZE];
    uint8_t *hash_binary = pkt->chunk_to_fetch;
    binary2hex(hash_binary, CHUNKHASHS_SIZE, hash);

    // search if hash is in chunks_ihave
    // if so, read this chunk's data send this chunk file
    int have_size = list_size(chunks_ihave);
    chunk *chunk_p;
    chunk *new_ck;
    int i_have_this_chunk = 0;
    for (int i = 0; i < have_size; i++) {
        chunk_p = (chunk *)(list_get(chunks_ihave, i));
        if(memcmp(chunk_p->sha1, hash, CHUNKHASHS_HEX_SIZE) == 0) {
            new_ck = chunk_init();
            new_ck->from_or_to_id = source_peer->id;
            new_ck->id = chunk_p->id;
            strcpy(new_ck->sha1, chunk_p->sha1);
            i_have_this_chunk = 1;
            break;
        }
    }

    // release chunks in list
    for(int i = 0; i < have_size; i++) {
        chunk_p = (chunk *)list_remove(chunks_ihave, 0);
        chunk_clean(chunk_p);
    }
    // release list
    list_clean(chunks_ihave);

    if(i_have_this_chunk) {
        // open chunk-file
        FILE *fp;
        if ((fp = fopen(config.chunk_file, "r")) == NULL) {
            printf("ERROR: FILE %s OPEM FAILED\n", config.chunk_file);
            return ;
        }

        char data_file[FILENAME_LEN];
        if (fgets(buf, FILENAME_LEN, fp) != NULL) {
            sscanf(buf, "%s %s", data_file, data_file);
        }

        fclose(fp);

        if ((fp = fopen(data_file, "r")) == NULL) {
            printf("ERROR: FILE %s OPEM FAILED\n", data_file);
            return ;
        }
        
        // read data
        fseek(fp, new_ck->id * BT_CHUNK_SIZE, SEEK_SET);
        if (fread(new_ck->data, sizeof(uint8_t), BT_CHUNK_SIZE, fp) < 0) {
            printf("ERROR: FILE %s READ FAILED\n", config.chunk_file);
            return ;
        }

        fclose(fp);

        // initialize list of chunks to send if it is NULL
        if (chunks_to_send == NULL) {
            chunks_to_send = list_init();
        }

        // if this peer is sending to source peer, then remove last sending chunk
        int chunks_to_send_size = chunks_to_send->size;
        for (int index = 0; index < chunks_to_send_size; index++) {
            chunk *tmp_ck = (chunk *)list_get(chunks_to_send, index);
            if (tmp_ck->from_or_to_id == source_peer->id) {
                list_remove(chunks_to_send, index);
                index--;
            }
        }

        list_add(chunks_to_send, chunks_to_send->size, new_ck);

        // send DATA packet
        if (chunks_to_send->size == 1) {
            send_DATA_pkt();
        }
    }
}

void process_DATA(data_packet *pkt, bt_peer_t *source_peer) {
    int size = list_size(chunks_to_download);   // how many chunks in chunks_to_download list
    chunk *chunk_p;                             // a chunk pointer

    short source_peer_id = source_peer->id;

    // check if this peer is downloading from target peer
    // if not, send a fake ack that equal to seq number in the packet
    int GET_sent = 0;
    if (peers_GET_pkt_sent == NULL) {
        peers_GET_pkt_sent = list_init();
    }
    int sent_size = peers_GET_pkt_sent->size;
    for (int i = 0; i < sent_size; i++) {
        short peer_id = *((short *)(list_get(peers_GET_pkt_sent, i)));
        if (peer_id == source_peer_id) {
            GET_sent = 1;
            break;
        }
    }
    if (!GET_sent) {
        u_int fake_ack = pkt->header.seq_num;
        ack_packet *fake_ack_pkt = create_ack_pkt(fake_ack);
        send_packet(source_peer, fake_ack_pkt, fake_ack_pkt->header.packet_len);
        free(fake_ack_pkt);
        return ;
    }

    // look for which chunk is this DATA packet belong to
    for (int i = 0; i < size; i++) {
        chunk_p = list_get(chunks_to_download, i);
        if (chunk_p->state == DOWNLOADING && chunk_p->from_or_to_id == source_peer->id) {
            break;
        }
    }

    // reset reconnect time
    chunk_p->reconnect_time = 0;
    
    // check sequence number
    u_int seq = pkt->header.seq_num;
    short data_len = pkt->header.packet_len - pkt->header.header_len;
    int seq_expect = chunk_p->window->last_ack_num + 1;


    printf("SEQ RECEIVE: %d SEQ EXPECT: %d\n", seq, seq_expect);


    if (seq == seq_expect) {
        // receive data
        memcpy(chunk_p->data + chunk_p->window->base_index, pkt->chunk_data, data_len);
        chunk_p->window->base_index += data_len;
        chunk_p->window->last_ack_num = seq_expect;
    }

    u_int ack = chunk_p->window->last_ack_num;

    // send ACK packet
    ack_packet *ack_pkt = create_ack_pkt(ack);
    send_packet(source_peer, ack_pkt, ack_pkt->header.packet_len);
    free(ack_pkt);

    // if this entire chunk has downloaded, check its correctness
    if (chunk_p->window->base_index >= BT_CHUNK_SIZE) {
        uint8_t *binary_hash = (uint8_t *)(malloc(CHUNKHASHS_SIZE));
        char hash[CHUNKHASHS_HEX_SIZE];
        shahash(chunk_p->data, BT_CHUNK_SIZE, binary_hash);
        binary2hex(binary_hash, CHUNKHASHS_SIZE, hash);

        // remove source_peer_id from peers_GET_pkt_sent
        for(int i = 0; i < sent_size; i++) {
            short *id = (short *)(list_get(peers_GET_pkt_sent, i));
            if (*id == source_peer_id) {
                list_remove(peers_GET_pkt_sent, i);
                free(id);
                break;
            }
        }

        if(memcmp(chunk_p->sha1, hash, CHUNKHASHS_HEX_SIZE) == 0) {
            // update chunk state
            chunk_p->state = FINISHED;

            // check if all chunks has finished, complete download
            chunk *c_p;
            int all_finished = 1;
            for (int i = 0; i < size; i++) {
                c_p = list_get(chunks_to_download, i);
                if (c_p->state != FINISHED) {
                    all_finished = 0;
                    break;
                }
            }
            if (all_finished) {
                complete_download();
            }
        } else {
            // data error, download again
            chunk_p->state = WAITING;
            chunk_p->from_or_to_id = -1;
            chunk_p->reconnect_time = 0;
            chunk_p->window->base_index = 0;
            chunk_p->window->last_ack_num = 0;
        }

        // release resource
        free(binary_hash);
    }
}

void process_ACK(ack_packet *pkt, bt_peer_t *source_peer) {
    int size = list_size(chunks_to_send);   // how many chunks in chunks_to_send list
    chunk *chunk_p;                         // a chunk pointer

    // if chunks_to_send is empty, return
    if(size == 0) {
        return ;
    }

    short source_peer_id = source_peer->id;

    // check if this peer is sending to target peer
    // if not, return
    int DATA_sending = 0;
    int i;
    for (i = 0; i < size; i++) {
        chunk_p = (chunk *)(list_get(chunks_to_send, i));
        if (chunk_p->from_or_to_id == source_peer_id) {
            DATA_sending = 1;
            break;
        }
    }
    if (!DATA_sending) {
        return ;
    }

    // ckeck ack number
    u_int ack = pkt->header.ack_num;
    int ack_expect = (chunk_p->window->base_index / PACKET_MAX_DATA_SIZE) + 1;
    if (ack >= ack_expect && ack < ack_expect + WINDOW_SIZE) {
        int step = ack - ack_expect + 1;
        chunk_p->window->base_index += (step * PACKET_MAX_DATA_SIZE);

        if (chunk_p->window->base_index == BT_CHUNK_SIZE) {
            // if sending finished, release resource
            chunk_clean(chunk_p);
            list_remove(chunks_to_send, i);
            send_DATA_pkt();
        } else {
            window *ww = chunk_p->window;
            if (step >= 8) {
                for (int i = 0; i < WINDOW_SIZE; i++) {
                    ww->wd[i] = 0;
                }
            } else {
                for (int i = step; i < WINDOW_SIZE; i++) {
                    ww->wd[i - step] = ww->wd[i];
                }
                for (int i = WINDOW_SIZE - step; i < WINDOW_SIZE; i++) {
                    ww->wd[i] = 0;
                }
            }

            for (int j = 0; j < WINDOW_SIZE; j++) {
                int next_index = ww->base_index + j * PACKET_MAX_DATA_SIZE;
                if(ww->wd[j] == 0 && next_index < BT_CHUNK_SIZE) {
                    u_int seq = (next_index / PACKET_MAX_DATA_SIZE) + 1;
                    data_packet* pkt = create_data_pkt(chunk_p->data + next_index, seq);
                    send_packet(source_peer, pkt, pkt->header.packet_len);
                    free(pkt);
                    ww->wd[j] = 1;
                }
            }
        }
    }
}

void process_DENIED() {
    // do nothing
    return ;
}
