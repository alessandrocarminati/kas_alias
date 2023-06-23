#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "item_list.h"
#include "duplicates_list.h"
#include "parse_linker_log.h"

void find_suffix(const char *name, const char *suffix, char *output_suffix){

	sprintf(output_suffix, "%s@%s", name, suffix);
}



int main() {
	struct item *head = {NULL};
	struct item *o_head = {NULL};
	struct item  *current;
	struct duplicate_item *duplicate, *duplicate_iterator;
	struct linker_object *lod, *lod_iterator;
	uint64_t	address;
	char		t, sym_name[MAX_NAME_SIZE], new_name[MAX_NAME_SIZE];

	printf("fetching loader producted map\n");
	lod=parseLinkerObjects("vmlinux.map");
/*
	lod_iterator=lod;
	while (lod_iterator != NULL) {
		printf("type=%s, address=0x%08lx, size=0x%08lx, filename=%s\n", lod_iterator->type, lod_iterator->address, lod_iterator->size, lod_iterator->filename);
		lod_iterator=lod_iterator->next;
		}
*/
//ffffffff814c8f10 T dev_fwnode

//	printf("symbol=dev_fwnode address=0xffffffff814c8f10 filename=%s\n", addr2filename(lod, 0xffffffff814c8f10 ));

	printf("Scanning nm data\n");
	while (scanf("%lx %c %99s\n", &address, &t, sym_name) == 3) {
		addItem(&head, sym_name, t, address);
		}


/*	current = head;
	while (current != NULL) {
		printf("%08lx %c %s\n", current->addr, current->stype, current->symb_name);
		current = current->next;
		}
*/
	printf("Sorting nm data\n");
	sortList(&head, BY_NAME);
/*
	current = head;
	while (current != NULL) {
		printf("%08lx %c %s\n", current->addr, current->stype, current->symb_name);
		current = current->next;
		}
*/
//	if (!insert_after(head, 0xffffffff811c9a50, "zone_watermark_ok_stocazzo", 0xffffffff811c9a50,'T')) return 1;
/*
	current = head;
	while (current != NULL) {
		printf("%08lx %c %s\n", current->addr, current->stype, current->symb_name);
		current = current->next;
		}
*/
	printf("Scanning nm data for duplicates\n");
	duplicate = findDuplicates(head);
/*
	duplicate_iterator=duplicate;
	while (duplicate_iterator != NULL) {
		printf("%08lx %c %s\n", duplicate_iterator->original_item->addr, duplicate_iterator->original_item->stype, duplicate_iterator->original_item->symb_name);
		duplicate_iterator=duplicate_iterator->next;
		}
*/

	printf("Applying suffixes\n");
	duplicate_iterator=duplicate;
	while (duplicate_iterator != NULL) {
			find_suffix(duplicate_iterator->original_item->symb_name, addr2filename(lod, 0xffffffff814c8f10), new_name);
			if (!insert_after(head, duplicate_iterator->original_item->addr, new_name, duplicate_iterator->original_item->addr, duplicate_iterator->original_item->stype)) return 1;
			duplicate_iterator=duplicate_iterator->next;
			}
        current = head;
        while (current != NULL) {
                printf("%08lx %c %s\n", current->addr, current->stype, current->symb_name);
                current = current->next;
                }
	return 0;
}
