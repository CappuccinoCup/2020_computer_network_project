#ifndef _PEER_CHUNK_H_
#define _PEER_CHUNK_H_

#include "chunk.h"
#include "sha.h"
#include "peer_list.h"

#define WINDOW_SIZE 8

typedef enum chunk_state {
    WAITING, DOWNLOADING, FINISHED
} chunk_state;

typedef struct window {
    // 0: empty
    // 1: waiting
    // 2: complete
    short wd[WINDOW_SIZE];
    int base_index;
    int last_ack_num;
} window;


typedef struct chunk {
    int id;
    char sha1[2 * SHA1_HASH_SIZE + 1];
    uint8_t data[BT_CHUNK_SIZE];

    list *owner_peers_id;

    chunk_state state;
    short from_or_to_id;    // the id of peer from or to which this chunk download or send
    short reconnect_time;   // how many time-out times not receive DATA packet

    window *window;
} chunk;

chunk* chunk_init();

void chunk_add_owner(chunk *ck, short peer_id);

void chunk_remove_owner(chunk *ck, short peer_id);

void chunk_clean(chunk *chunk);

#endif
