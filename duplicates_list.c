// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "item_list.h"
#include "duplicates_list.h"

#ifdef DEBUG
int duplicates_alloc_cnt;
#endif


struct duplicate_item *find_duplicates(struct item *list)
{
	struct duplicate_item *duplicates = NULL;
	struct duplicate_item *current_duplicate = NULL;
	struct item *current_item = list;
	struct item *prev_item = NULL;
	struct duplicate_item *new_duplicate;
	bool   prev_was_duplicate = false;

	while (current_item) {
		if (prev_item && (strcmp(current_item->symb_name, prev_item->symb_name) == 0) ||
		    prev_was_duplicate) {
			if (!duplicates) {
#ifdef DEBUG
				duplicates_alloc_cnt++;
#endif
				duplicates = (struct duplicate_item *)
					malloc(sizeof(struct duplicate_item));
				duplicates->original_item = prev_item;
				duplicates->next = NULL;
				current_duplicate = duplicates;
				if (prev_was_duplicate)
					prev_was_duplicate = false;
				else
					prev_was_duplicate = true;
			} else {
#ifdef DEBUG
				duplicates_alloc_cnt++;
#endif
				new_duplicate = (struct duplicate_item *)
					malloc(sizeof(struct duplicate_item));
				new_duplicate->original_item = prev_item;
				new_duplicate->next = NULL;
				current_duplicate->next = new_duplicate;
				current_duplicate = new_duplicate;
				if (prev_was_duplicate)
					prev_was_duplicate = false;
				else
					prev_was_duplicate = true;
			}
		}

		prev_item = current_item;
		current_item = current_item->next;
	}

	return duplicates;
}

void free_duplicates(struct duplicate_item **duplicates)
{
	struct duplicate_item *app, *duplicates_iterator = *duplicates;

	while (duplicates_iterator) {
		app = duplicates_iterator;
		duplicates_iterator = duplicates_iterator->next;
		free(app);
#ifdef DEBUG
		duplicates_alloc_cnt--;
#endif
	}
	*duplicates = NULL;
}
