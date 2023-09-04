/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ITEM_LIST_H
#define ITEM_LIST_H

#include <stdint.h>

#define MAX_NAME_SIZE 256
#define HASH_TABLE_SIZE (1<<14)

extern int hash_collision_max;

struct item {
	char symb_name[MAX_NAME_SIZE];
	uint64_t addr;
	char stype;
	struct item *next;
};

struct hash_node {
	char key[MAX_NAME_SIZE];
	int count;
	struct hash_node *next;
};

struct hash_index {
	struct hash_node *table[HASH_TABLE_SIZE];
};

struct heads {
	struct item *head;
	struct item *tail;
	struct hash_index *index;
};

struct heads *init_heads();
void add_item(struct heads *, char *, uint64_t, char);
void cleanup_list(struct heads *);
int item_counter(struct heads *, char *);
void add_item_at(struct item *, char *, uint64_t, char);
#endif
