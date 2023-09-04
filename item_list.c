#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "item_list.h"

// Hash function as djb2
static int hash_function(char *key)
{
	unsigned long hash = 5381;
	int c;

	while ((c = *key++))
		hash = ((hash << 5) + hash) + c;

	return hash % HASH_TABLE_SIZE;
}

static void cleanup_hash_index(struct hash_index *index)
{
	int i;

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		struct hash_node *current = index->table[i];
		while (current != NULL) {
			struct hash_node *temp = current;
			current = current->next;
			free(temp);
		}
	}
	free(index);
}

static void update_hash_index(struct hash_index *index, char *key)
{
	int index_value = hash_function(key);
	struct hash_node *current = index->table[index_value];
	while (current != NULL) {
		if (strcmp(current->key, key) == 0) {
			current->count++;
			return;
		}
		current = current->next;
	}

	struct hash_node *new_node = malloc(sizeof(struct hash_node));
	if (new_node == NULL) {
		perror("Failed to allocate memory for hash node");
		exit(EXIT_FAILURE);
	}

	strncpy(new_node->key, key, MAX_NAME_SIZE);
	new_node->count = 1;
	new_node->next = index->table[index_value];
	index->table[index_value] = new_node;
}

static struct hash_index *init_hash_index()
{
	struct hash_index *index = malloc(sizeof(struct hash_index));
	if (index == NULL) {
		perror("Failed to allocate memory for hash index");
		exit(EXIT_FAILURE);
	}
	memset(index, 0, sizeof(struct hash_index));
	return index;
}

struct heads *init_heads()
{
	struct heads *h = malloc(sizeof(struct heads));
	if (h == NULL) {
		perror("Failed to allocate memory for heads");
		exit(EXIT_FAILURE);
	}
	h->head = NULL;
	h->tail = NULL;
	h->index = init_hash_index();
	return h;
}

void add_item(struct heads *h, char *key, uint64_t addr, char stype)
{
	struct item *new_item = malloc(sizeof(struct item));
	if (new_item == NULL) {
		perror("Failed to allocate memory for item");
		exit(EXIT_FAILURE);
	}

	strncpy(new_item->symb_name, key, MAX_NAME_SIZE);
	new_item->addr = addr;
	new_item->stype = stype;
	new_item->next = NULL;

	if (h->head == NULL) {
		h->head = new_item;
		h->tail = new_item;
	} else {
		h->tail->next = new_item;
		h->tail = new_item;
	}

	update_hash_index(h->index, key);
}

//return the address of the next element to iterate, reurn itm on fail.
void add_item_at(struct item *itm, char *symb_name, uint64_t addr, char stype)
{
	struct item *new_item;

	if (!itm) {
		perror("Failed to allocate memory for item");
		exit(EXIT_FAILURE);
	}
	new_item = malloc(sizeof(struct item));
	strncpy(new_item->symb_name, symb_name, MAX_NAME_SIZE);
	new_item->addr = addr;
	new_item->stype = stype;
	new_item->next = itm->next;
	itm->next = new_item;
	return;
}

void cleanup_list(struct heads *h)
{
	struct item *current;

	if (!h)
		return;

	current = h->head;
	if (current) {
		cleanup_hash_index(h->index);
		while (current != NULL) {
			struct item *temp = current;
			current = current->next;
			free(temp);
		}
		memset(h, 0, sizeof(struct heads));
		free(h);
	}
}

int item_counter(struct heads *h, char *key) {
	int index_value = hash_function(key);

	struct hash_node *current = h->index->table[index_value];
	while (current != NULL) {
		if (strcmp(current->key, key) == 0) {
			return current->count;
			}
		current = current->next;
	}
	return -1;
}


