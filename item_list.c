#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "item_list.h"

int hash_collision_max = 0;

#define ROTL32(x, r) ((x << r) | (x >> (32 - r)))
#define MURMUR3_SEED 0x55aa9966
static int hash_function(const char *key) {
	const uint8_t *data = (const uint8_t *)key;
	const uint32_t len = (uint32_t)strlen(key);
	const uint32_t c1 = 0xcc9e2d51;
	const uint32_t c2 = 0x1b873593;
	uint32_t hash = MURMUR3_SEED;
	const uint32_t *blocks;
	const uint8_t *tail;
	uint32_t k1;
	int i;

	blocks = (const uint32_t *)(data + (len / 4) * 4);
	for (i = 0; i < (int)(len / 4); i++) {
		uint32_t k1 = blocks[i];
		k1 *= c1;
		k1 = ROTL32(k1, 15);
		k1 *= c2;

		hash ^= k1;
		hash = ROTL32(hash, 13);
		hash = hash * 5 + 0xe6546b64;
	}

	tail = (const uint8_t *)(data + (len / 4) * 4);
	k1 = 0;
	switch (len & 3) {
		case 3:
			k1 ^= tail[2] << 16;
		case 2:
			k1 ^= tail[1] << 8;
		case 1:
			k1 ^= tail[0];
			k1 *= c1;
			k1 = ROTL32(k1, 15);
			k1 *= c2;
			hash ^= k1;
	}

	hash ^= len;
	hash ^= (hash >> 16);
	hash *= 0x85ebca6b;
	hash ^= (hash >> 13);
	hash *= 0xc2b2ae35;
	hash ^= (hash >> 16);

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
	int ctr=0;

	while (current != NULL) {
		if (strcmp(current->key, key) == 0) {
			current->count++;
			if (ctr > hash_collision_max) {
				hash_collision_max = ctr;
			}
			return;
		}
		ctr++;
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


