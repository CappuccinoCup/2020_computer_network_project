#include "peer_chunk.h"

#include <malloc.h>

chunk* chunk_init() {
    chunk *ck = (chunk *)(malloc(sizeof(chunk)));
    window *ww = (window *)(malloc(sizeof(window)));
    list *owners = list_init();

    ww->base_index = 0;
    ww->last_ack_num = 0;
    for (int i = 0; i < WINDOW_SIZE; i++) {
        ww->wd[i] = 0;
    }

    ck->owner_peers_id = owners;
    ck->window = ww;

    ck->state = WAITING;
    ck->from_or_to_id = -1;
    ck->reconnect_time = 0;

    return ck;
}

void chunk_add_owner(chunk* ck, short peer_id) {
    short *id = (short *)(malloc(sizeof(short)));
    *id = peer_id;
    list_add(ck->owner_peers_id, ck->owner_peers_id->size, id);
}

void chunk_remove_owner(chunk *ck, short peer_id) {
    list* owners = ck->owner_peers_id;
    short *id;
    for(int i = 0; i < owners->size; i++) {
        id = (short *)(list_get(owners, i));
        if(*id == peer_id) {
            list_remove(owners, i);
            free(id);
            i--;
        }
    }
}

void chunk_clean(chunk *ck) {
    // release ids
    list* owners = ck->owner_peers_id;
    int size = owners->size;
    short *id;
    for (int i = 0; i < size; i++) {
        id = (short *)(list_get(owners, i));
        free(id);
    }
    
    // release chunk
    list_clean(ck->owner_peers_id);
    free(ck->window);
    free(ck);
}
