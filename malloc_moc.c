#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "debug.h"

static void* (*original_malloc)(size_t size) = NULL;

static int cnt16 = 0;
static int cnt280 = 0;

void* malloc(size_t size)
{
	if (!original_malloc)
		original_malloc = dlsym(RTLD_NEXT, "malloc"); // Get the original malloc function

	if ( (size == 16) && ((cnt16++)>=ITEM_CNT)) return NULL;
	if ( (size == 280) && ((cnt280++)>=DUPLICATES_CNT)) return NULL;

	void* ptr = original_malloc(size);

	return ptr;
}
