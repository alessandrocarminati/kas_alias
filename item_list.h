/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ITEM_LIST_H
#define ITEM_LIST_H
#include <stdint.h>

#define MAX_NAME_SIZE 256
#define BY_ADDRESS 1
#define BY_NAME 2

struct item {
	char		symb_name[MAX_NAME_SIZE];
	uint64_t	addr;
	char		stype;
	struct item	*next;
};

void build_index(struct item *list);
struct item *add_item(struct item **list, const char *name, char stype, uint64_t addr);
void sort_list(struct item **list, int sort_by);
struct item *merge(struct item *left, struct item *right, int sort_by);
struct item *merge_sort(struct item *head, int sort_by);
void sort_list_m(struct item **head, int sort_by);
int insert_after(struct item *list, const uint64_t search_addr,
		 const char *name, uint64_t addr, char stype);
void free_items(struct item **head);
#endif
