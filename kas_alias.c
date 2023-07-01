// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "item_list.h"
#include "duplicates_list.h"
//#define DEBUG

int suffix_serial;
static void create_suffix(const char *name, char *output_suffix)
{
	sprintf(output_suffix, "%s@%d", name, suffix_serial++);
}

int main(int argc, char *argv[])
{
	struct item *head = {NULL};
	struct item *last = {NULL};
	struct item  *current;
	struct duplicate_item *duplicate, *duplicate_iterator;
	uint64_t address;
	int verbose_mode = 0;
	char t, sym_name[MAX_NAME_SIZE], new_name[MAX_NAME_SIZE+15]; // 15 is a safemargin to prevent overflows
	bool need_2_process = true;
	FILE *fp;

	if (argc < 2 || argc > 3) {
		printf("Usage: %s <nmfile> [-verbose]\n", argv[0]);
		return 1;
	}
	if (argc == 3 && strcmp(argv[2], "-verbose") == 0)
		verbose_mode = 1;

	if (verbose_mode)
		printf("Scanning nm data(%s)\n", argv[1]);
	fp = fopen(argv[1], "r");
	while (fscanf(fp, "%lx %c %99s\n", &address, &t, sym_name) == 3) {
		if (strstr(sym_name, "@1") != NULL) {
			if (verbose_mode && need_2_process)
				printf("Already processed\n");
			need_2_process = false;
			}
		last = add_item(&last, sym_name, t, address);
		if (!head)
			head = last;
	}
	fclose(fp);
	if (need_2_process) {
		if (verbose_mode)
			printf("Sorting nm data\n");
		sort_list_m(&head, BY_NAME);
		if (verbose_mode)
			printf("Scanning nm data for duplicates\n");
		duplicate = find_duplicates(head);
		if (verbose_mode)
			printf("Applying suffixes\n");
		build_index(head);
		duplicate_iterator = duplicate;
		while (duplicate_iterator) {
			create_suffix(duplicate_iterator->original_item->symb_name, new_name);
			if (!insert_after(head, duplicate_iterator->original_item->addr, new_name,
					  duplicate_iterator->original_item->addr,
					  duplicate_iterator->original_item->stype))
				return 1;
			duplicate_iterator = duplicate_iterator->next;
		}
		sort_list_m(&head, BY_ADDRESS);
	}
	current = head;
	while (current) {
		printf("%08lx %c %s\n", current->addr, current->stype, current->symb_name);
		current = current->next;
	}
#ifdef DEBUG
	printf("Alloc statistics before: remained items=%d, remained duplicates=%d\n",
		item_alloc_cnt, duplicates_alloc_cnt);
#endif
	free_items(&head);
	free_duplicates(&duplicate);
#ifdef DEBUG
	printf("Alloc statistics after: remained items=%d, remained duplicates=%d\n",
		item_alloc_cnt, duplicates_alloc_cnt);
#endif

	return 0;
}
