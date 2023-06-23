#ifndef DUPLICATES_LIST_H
#define DUPLICATES_LIST_H

#include "item_list.h"

struct duplicate_item {
	struct item *original_item;
	struct duplicate_item *next;
};

struct duplicate_item* findDuplicates(struct item* list);

#endif
