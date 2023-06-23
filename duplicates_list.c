#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "item_list.h"
#include "duplicates_list.h"

struct duplicate_item* findDuplicates(struct item* list) {
    struct duplicate_item* duplicates = NULL;
    struct duplicate_item* current_duplicate = NULL;
    struct item* current_item = list;
    struct item* prev_item = NULL;

    while (current_item != NULL) {
        if (prev_item != NULL && strcmp(current_item->symb_name, prev_item->symb_name) == 0) {
            // Found a duplicate
            if (duplicates == NULL) {
                duplicates = (struct duplicate_item*)malloc(sizeof(struct duplicate_item));
                duplicates->original_item = prev_item;
                duplicates->next = NULL;
                current_duplicate = duplicates;
            } else {
                struct duplicate_item* new_duplicate = (struct duplicate_item*)malloc(sizeof(struct duplicate_item));
                new_duplicate->original_item = prev_item;
                new_duplicate->next = NULL;
                current_duplicate->next = new_duplicate;
                current_duplicate = new_duplicate;
            }

            struct duplicate_item* new_duplicate = (struct duplicate_item*)malloc(sizeof(struct duplicate_item));
            new_duplicate->original_item = current_item;
            new_duplicate->next = NULL;
            current_duplicate->next = new_duplicate;
            current_duplicate = new_duplicate;
        }

        prev_item = current_item;
        current_item = current_item->next;
    }

    return duplicates;
}
