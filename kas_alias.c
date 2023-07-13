// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <regex.h>

#include "item_list.h"
#include "duplicates_list.h"

#define SYMB_IS_TEXT(s) ((((s)->stype) == 't') ||  (((s)->stype) == 'T'))
#define FNOMATCH 0
#define FMATCH 1
#define EREGEX 2

const char *ignore_regex[] = {
	"^__cfi_[a-zA-Z0-9_\\.]*$",
	"^__pfx_[a-zA-Z00-9_\\.]*$",
	"^lock_class[a-zA-Z00-9_\\.]*$",
	"^__wkey[a-zA-Z00-9_\\.]*$",
	"^__mkey[a-zA-Z00-9_\\.]*$" 
	"^__key[a-zA-Z00-9_\\.]*$"
};

int suffix_serial;

static inline void verbose_msg(bool verbose, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (verbose)
		printf(fmt, args);

	va_end(args);
}

static void create_suffix(const char *name, char *output_suffix)
{
	sprintf(output_suffix, "%s__alias__%d", name, suffix_serial++);
}

static int filter_symbols(char *symbol, const char **ignore_list, int regex_no) {
	regex_t regex;
	int res, i;

	for (i=0; i<regex_no; i++) {
		res = regcomp(&regex, ignore_list[i], REG_EXTENDED);
		if (res)
			return -EREGEX;

		res = regexec(&regex, symbol, 0, NULL, 0);
		switch (res) {
			case 0:
				return FMATCH;
			case REG_NOMATCH:
				break;
			default:
				return -EREGEX;
		}

	}

	regfree(&regex);
	return FNOMATCH;
}

int main(int argc, char *argv[])
{
	char t, sym_name[MAX_NAME_SIZE], new_name[MAX_NAME_SIZE + 15];
	struct duplicate_item  *duplicate_iterator;
	struct duplicate_item *duplicate;
	struct item *head = {NULL};
	bool need_2_process = true;
	struct item *last = {NULL};
	struct item  *current;
	int verbose_mode = 0;
	uint64_t address;
	FILE *fp;
	int res;

	if (argc < 2 || argc > 3) {
		printf("Usage: %s <nmfile> [-verbose]\n", argv[0]);
		return 1;
	}

	if (argc == 3 && strcmp(argv[2], "-verbose") == 0)
		verbose_mode = 1;

	verbose_msg(verbose_mode, "Scanning nm data(%s)\n", argv[1]);

	fp = fopen(argv[1], "r");
	if (!fp) {
		printf("Can't open input file.\n");
		return 1;
	}

	while (fscanf(fp, "%lx %c %99s\n", &address, &t, sym_name) == 3) {
		if (strstr(sym_name, "__alias__1") != NULL) {
			if (verbose_mode && need_2_process)
				printf("Already processed\n");
			need_2_process = false;
			}
		last = add_item(&last, sym_name, t, address);
		if (!last) {
			printf("Error in allocate memory\n");
			free_items(&head);
			return 1;
		}

		if (!head)
			head = last;
	}

	fclose(fp);

	if (need_2_process) {
		verbose_msg(verbose_mode, "Sorting nm data\n");
		sort_list_m(&head, BY_NAME);
		verbose_msg(verbose_mode, "Scanning nm data for duplicates\n");
		duplicate = find_duplicates(head);
		if (!duplicate) {
			printf("Error in duplicates list\n");
			return 1;
		}

		verbose_msg(verbose_mode, "Applying suffixes\n");
		build_index(head);
		duplicate_iterator = duplicate;
		while (duplicate_iterator) {
			if ((res = filter_symbols(duplicate_iterator->original_item->symb_name,
			   ignore_regex, sizeof(ignore_regex)/sizeof(ignore_regex[0])) != FMATCH) &&
			   SYMB_IS_TEXT(duplicate_iterator->original_item)) {
				if (res < 0)
					return 1;

				create_suffix(duplicate_iterator->original_item->symb_name, new_name);
				if (!insert_after(head, duplicate_iterator->original_item->addr, new_name,
						  duplicate_iterator->original_item->addr,
						  duplicate_iterator->original_item->stype))
					return 1;
			}

			duplicate_iterator = duplicate_iterator->next;
		}

		sort_list_m(&head, BY_ADDRESS);
	}
	current = head;
	while (current) {
		printf("%08lx %c %s\n", current->addr, current->stype, current->symb_name);
		current = current->next;
	}

	free_items(&head);
	free_duplicates(&duplicate);

	return 0;
}
