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



int main(int argc, char *argv[]) {
	struct item *head = {NULL};
	struct item *last = {NULL};
	struct item *o_head = {NULL};
	struct item  *current;
	struct duplicate_item *duplicate, *duplicate_iterator;
	struct linker_object *lod, *lod_iterator;
	uint64_t address;
	int verbose_mode = 0;
	char t, sym_name[MAX_NAME_SIZE], new_name[MAX_NAME_SIZE];
	FILE *fp;

	if (argc < 3 || argc > 4) {
		printf("Usage: %s <nmfile> <vmlinux.map> [-verbose]\n", argv[0]);
		return 1;
		}
	if (argc == 4 && strcmp(argv[3], "-verbose") == 0) {
		verbose_mode = 1;
		}

	if (verbose_mode) printf("fetching loader producted map (%s)\n", argv[2]);
	lod=parseLinkerObjects(argv[2]);

	if (verbose_mode) printf("Scanning nm data(%s)\n", argv[1]);
	fp = fopen (argv[1], "r");
	while (fscanf(fp, "%lx %c %99s\n", &address, &t, sym_name) == 3) {
		last=addItem(&last, sym_name, t, address);
		if (head==NULL) head=last;
		}
	fclose(fp);
	if (verbose_mode) printf("Sorting nm data\n");
	sortList_m(&head, BY_NAME);
	if (verbose_mode) printf("Scanning nm data for duplicates\n");
	duplicate = findDuplicates(head);
	if (verbose_mode) printf("Applying suffixes\n");
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
