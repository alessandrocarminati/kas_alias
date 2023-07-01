/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DUPLICATES_LIST_H
#define DUPLICATES_LIST_H

#include "item_list.h"
//#define DEBUG

struct duplicate_item {
	struct item *original_item;
	struct duplicate_item *next;
};

#ifdef DEBUG
extern int duplicates_alloc_cnt;
#endif

struct duplicate_item *find_duplicates(struct item *list);
void free_duplicates(struct duplicate_item **duplicates);

#endif
