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

static inline void inc_duplicates_cnt(void)
{
	duplicates_alloc_cnt++;
}

static inline void dec_duplicates_cnt(void)
{
	duplicates_alloc_cnt--;
}

#else

static inline void inc_duplicates_cnt(void) {};
static inline void dec_duplicates_cnt(void) {};

#endif


struct duplicate_item *find_duplicates(struct item *list)
{
	struct duplicate_item *current_duplicate = NULL;
	struct duplicate_item *duplicates = NULL;
	struct duplicate_item *new_duplicate;
	struct item *current_item = list;
	bool prev_was_duplicate = false;
	struct item *prev_item = NULL;

	while (current_item) {
		if ((prev_item && (strcmp(current_item->symb_name, prev_item->symb_name) == 0)) ||
		    prev_was_duplicate) {
			if (!duplicates) {
				inc_duplicates_cnt();
				duplicates = malloc(sizeof(struct duplicate_item));
				if (!duplicates)
					return NULL;
				duplicates->original_item = prev_item;
				duplicates->next = NULL;
				current_duplicate = duplicates;

				if (prev_was_duplicate)
					prev_was_duplicate = false;
				else
					prev_was_duplicate = true;
			} else {
				inc_duplicates_cnt();
				new_duplicate = malloc(sizeof(struct duplicate_item));
				if (!new_duplicate) {
					free_duplicates(&duplicates);
					return NULL;
				}

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
	struct duplicate_item *duplicates_iterator = *duplicates;
	struct duplicate_item *app;

	while (duplicates_iterator) {
		app = duplicates_iterator;
		duplicates_iterator = duplicates_iterator->next;
		free(app);
		dec_duplicates_cnt();
	}

	*duplicates = NULL;
}
