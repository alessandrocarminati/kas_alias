/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DEBUG_H
#define DEBUG_H

#include <stdarg.h>
#include <stdbool.h>

#include "item_list.h"
#include "duplicates_list.h"

#define DUPLICATES_CNT 50
#define ITEM_CNT 50

#define PRINT_STATS_ITM __attribute__ ((cleanup(print_stats_itm)))
#define PRINT_STATS_DPL __attribute__ ((cleanup(print_stats_dpl)))

#ifdef DEBUG
extern int duplicates_alloc_cnt;
extern int item_alloc_cnt;

static inline void print_stats_itm(void *p)
{
	printf("DEBUG - Alloc statistics remained items=%d\n", item_alloc_cnt);
}

static inline void print_stats_dpl(void *p)
{
	printf("DEBUG - Alloc statistics remained duplicates=%d\n", item_alloc_cnt);
}
#else
static inline void print_stats_itm(void *p) {};
static inline void print_stats_dpl(void *p) {};
#endif

static inline void verbose_msg(bool verbose, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (verbose)
		printf(fmt, args);

	va_end(args);
}

#endif
