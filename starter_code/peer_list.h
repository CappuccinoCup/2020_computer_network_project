#ifndef _PEER_LIST_H
#define _PEER_LIST_H

typedef struct node {
    void *data;
    struct node *prev;
    struct node *next;
} node;

typedef struct list {
    node *head;
    node *tail;
    int size;
} list;


list* list_init();

int list_size(list *list);

void list_add(list *list, int index, void *data);

void *list_get(list *list, int index);

void* list_remove(list *list, int index);

void list_clean(list *list);

#endif 
