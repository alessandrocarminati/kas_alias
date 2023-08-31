// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <regex.h>
#include <ctype.h>

#include "item_list.h"
#include "duplicates_list.h"
#include "a2l.h"

#define SYMB_IS_TEXT(s) ((((s)->stype) == 't') ||  (((s)->stype) == 'T'))
#define SYMB_IS_DATA(s) ((((s)->stype) == 'b') ||  (((s)->stype) == 'B') || \
			 (((s)->stype) == 'd') ||  (((s)->stype) == 'D') || \
			 (((s)->stype) == 'r') ||  (((s)->stype) == 'R'))
#define NEED2NORMALIZE(str_to_norm, chr_pos)
	(!isalnum((str_to_norm)[(chr_pos)]) && ((str_to_norm)[(chr_pos)] != '@'))
#ifdef CONFIG_KALLSYMS_ALIAS_DATA
#define SYMB_NEEDS_ALIAS(s) (SYMB_IS_TEXT(s) || SYMB_IS_DATA(s))
#else
#define SYMB_NEEDS_ALIAS(s) SYMB_IS_TEXT(s)
#endif
#define FNOMATCH 0
#define FMATCH 1
#define EREGEX 2

const char *ignore_regex[] = {
	"^__cfi_.*$",				// __cfi_ preamble
#ifndef CONFIG_KALLSYMS_ALIAS_DATA_ALL
	"^_*TRACE_SYSTEM.*$",
	"^__already_done\\.[0-9]+$",		// Call a function once data
	"^___tp_str\\.[0-9]+$",
	"^___done\\.[0-9]+$",
	"^__print_once\\.[0-9]+$",
	"^_rs\\.[0-9]+$",
	"^__compound_literal\\.[0-9]+$",
	"^___once_key\\.[0-9]+$",
	"^__func__\\.[0-9]+$",
	"^__msg\\.[0-9]+$",
	"^CSWTCH\\.[0-9]+$",
	"^__flags\\.[0-9]+$",
	"^__wkey.*$",
	"^__mkey.*$",
	"^__key.*$",
#endif
	"^__pfx_.*$"				// NOP-padding
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

static void create_file_suffix(const char *name, uint64_t address, char *output_suffix, char *cwd)
{
	const char *f_path;
	char *buf;
	int i = 0;

	buf = addr2line_get_lines(address);
	f_path = remove_subdir(cwd, buf);
	if (f_path) {
		sprintf(output_suffix, "%s@%s", name, f_path);
		while (*(output_suffix + i) != '\0') {
			if (NEED2NORMALIZE(output_suffix, i))
				*(output_suffix + i) = '_';
			i++;
			}
	} else {
		create_suffix(name, output_suffix);
	}
}

static int filter_symbols(char *symbol, const char **ignore_list, int regex_no)
{
	regex_t regex;
	int res, i;

	for (i = 0; i < regex_no; i++) {
		res = regcomp(&regex, ignore_list[i], REG_EXTENDED);
		if (res)
			return -EREGEX;

		res = regexec(&regex, symbol, 0, NULL, 0);
		regfree(&regex);
		switch (res) {
		case 0:
			return FMATCH;
		case REG_NOMATCH:
			break;
		default:
			return -EREGEX;
		}
	}

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

	if (!addr2line_init(get_addr2line(A2L_CROSS), get_vmlinux(argv[1])))
		return 1;

	while (fscanf(fp, "%lx %c %99s\n", &address, &t, sym_name) == 3) {
		if (strstr(sym_name, "@_")) {
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
			res = filter_symbols(duplicate_iterator->original_item->symb_name,
					     ignore_regex, sizeof(ignore_regex) /
					     sizeof(ignore_regex[0]));
			if (res != FMATCH &&
			    SYMB_NEEDS_ALIAS(duplicate_iterator->original_item)) {
				if (res < 0)
					return 1;

				create_file_suffix(duplicate_iterator->original_item->symb_name,
						   duplicate_iterator->original_item->addr,
						   new_name, vmlinux_path);
				if (!insert_after(head, duplicate_iterator->original_item->addr,
						  new_name, duplicate_iterator->original_item->addr,
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
	addr2line_cleanup();
	return 0;
}
