#include "peer_list.h"

#include <malloc.h>

list* list_init() {
    list *l = (list *)(malloc(sizeof(list)));
    l->head = (node *)(malloc(sizeof(node)));
    l->tail = (node *)(malloc(sizeof(node)));

    // link head and tail
    l->head->next = l->tail;
    l->tail->prev = l->head;
    
    l->size = 0;

    return l;
}

int list_size(list *list) {
    if(list != NULL) {
        return list->size;
    } else {
        return -1;
    }
}

void list_add(list *list, int index, void *data) {
    if(list == NULL || index < 0 || index > list->size) {
        return ;
    }

    node *new_node = (node *)(malloc(sizeof(node)));
    new_node->data = data;

    node *curr = list->head;
    for(int i = 0; i < index; i++) {
        curr = curr->next;
    }

    curr->next->prev = new_node;
    new_node->next = curr->next;
    new_node->prev = curr;
    curr->next = new_node;

    list->size++;
}

void *list_get(list *list, int index) {
    if(list == NULL || index < 0 || index > list->size) {
        return NULL;
    }

    node *curr = list->head->next;
    for(int i = 0; i < index; i++) {
        curr = curr->next;
    }

    return curr->data;
}

void* list_remove(list *list, int index) {
    if(list == NULL || index < 0 || index > list->size) {
        return NULL;
    }

    node *curr = list->head->next;
    for(int i = 0; i < index; i++) {
        curr = curr->next;
    }

    void *data = curr->data;

    curr->prev->next = curr->next;
    curr->next->prev = curr->prev;
    free(curr);

    list->size--;

    return data;
}

void list_clean(list *list) {
    while (list->size > 0) {
        list_remove(list, 0);
    }
    free(list->head);
    free(list->tail);
    free(list);
}
