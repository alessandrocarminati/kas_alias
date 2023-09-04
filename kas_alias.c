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

#include "a2l.h"
#include "conf.h"
#include "item_list.h"

//#define DEFER(defer_func) __attribute__ ((cleanup(defer_func)))
#define SYMB_IS_TEXT(s) ((((s)->stype) == 't') ||  (((s)->stype) == 'T'))
#define SYMB_IS_DATA(s) ((((s)->stype) == 'b') ||  (((s)->stype) == 'B') || \
			 (((s)->stype) == 'd') ||  (((s)->stype) == 'D') || \
			 (((s)->stype) == 'r') ||  (((s)->stype) == 'R'))
#define NEED2NORMALIZE(str_to_norm, chr_pos) \
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
		vprintf(fmt, args);

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

#ifdef CONFIG_KALLSYMS_ALIAS_DATA
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
#endif

static void printnm(struct heads *h, char *fn)
{
	struct item *item_iterator;
	FILE *of;

	of = fopen(fn, "w");
	item_iterator = h->head;
	while (item_iterator) {
		fprintf(of, "%08lx %c %s\n", item_iterator->addr, item_iterator->stype, item_iterator->symb_name);
		item_iterator = item_iterator->next;
	}
	fclose(of);
}

void cleanup(struct conf *c, struct heads *h)
{
	free_cfg(c);
	cleanup_list(h);
}

int main(int argc, char *argv[])
{
	struct conf *cfg;
	char t, sym_name[MAX_NAME_SIZE], new_name[MAX_NAME_SIZE + 15];
	struct heads *h = init_heads();
	struct item *item_iterator;
	bool need_2_process = true;
	uint64_t address;
	FILE *fp;
#ifdef CONFIG_KALLSYMS_ALIAS_DATA
	int res;
#endif

	cfg = parse_command_line(argc, argv);
	if (!cfg) {
		conf_error(argv[0], cfg);
		cleanup(cfg, h);
		return 1;
	}


	verbose_msg(cfg->verbose, "Scanning nm data(%s)\n", argv[1]);

//	printf("config{%s, %s, %s, %s, %d}\n", cfg->nm_data, cfg->addr2line_cmd, cfg->vmlinux, cfg->out_file, cfg->verbose);
	fp = fopen(cfg->nm_data, "r");
	if (!fp) {
		printf("Can't open nm_data, file.\n");
		cleanup(cfg, h);
		return 1;
	}

	if (!addr2line_init(cfg->addr2line_cmd, cfg->vmlinux)){
		printf("Can't initialize addr2line, file.\n");
		fclose(fp);
		cleanup(cfg, h);
		return 1;
	}

	while (fscanf(fp, "%lx %c %99s\n", &address, &t, sym_name) == 3) {
		if (strstr(sym_name, "@_")) {
			if (cfg->verbose && need_2_process)
				printf("Already processed\n");
			need_2_process = false;
			}
		add_item(h, sym_name, address, t);
	}

	fclose(fp);

	printf("#################################################### hash_collision_max = %d \n", hash_collision_max);
//	printnm(h);

//	printf("##################################################################################################################################\n");
//	printf("##################################################################################################################################\n");
//	printf("##################################################################################################################################\n");
//	printf("##################################################################################################################################\n");
//	printf("##################################################################################################################################\n");

//	printf("reach here\n");
	if (need_2_process) {
//		printf("need_2_process\n");
		item_iterator = h->head;
		while (item_iterator) {
			if (item_counter(h, item_iterator->symb_name) > 1) {
//				printf("-> %s\n", item_iterator->symb_name);

#ifdef CONFIG_KALLSYMS_ALIAS_DATA
				res = filter_symbols(item_iterator->symb_name,
						     ignore_regex,
						     sizeof(ignore_regex) /
						     sizeof(ignore_regex[0]));
				if (res != FMATCH &&
				    SYMB_NEEDS_ALIAS(item_iterator)) {
					if (res < 0) {
						printf("symbol matching error\n");
						cleanup(cfg, h);
						return 1;
					}
#else
				if (SYMB_NEEDS_ALIAS(item_iterator)) {
#endif
					create_file_suffix(item_iterator->symb_name,
							   item_iterator->addr,
							   new_name, vmlinux_path);
//					printf("--> %s\n", new_name);
					add_item_at(item_iterator, new_name,
							  item_iterator->addr, item_iterator->stype);
				}
			}
		item_iterator = item_iterator->next;
		}
	}

	printnm(h, cfg->out_file);

	addr2line_cleanup();
	cleanup(cfg, h);
	return 0;
}
