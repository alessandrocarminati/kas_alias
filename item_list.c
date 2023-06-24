#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "item_list.h"

struct item *list_index[96]={0};

void build_index(struct item *list){
	struct item *current = list;
	char current_first_letter=' ';

//	printf("[head] -> 0x%08lx\n", list);
	while (current != NULL) {
		if (current->symb_name[0]!=current_first_letter) {
			current_first_letter=current->symb_name[0];
			list_index[current_first_letter-32]=current;
			}
		current=current->next;
		}
//	for (int i=0; i<96; i++) printf("[%d] -> 0x%08lx\n", i, list_index[i]);
}

struct item *add_item(struct item **list, const char *name, char stype, uint64_t addr) {
	struct item* new_item = (struct item*)malloc(sizeof(struct item));
	strncpy(new_item->symb_name, name, MAX_NAME_SIZE);
	new_item->addr = addr;
	new_item->stype = stype;
	new_item->next = NULL;

	if (*list == NULL) {
		*list = new_item;
		} else {
			struct item* current = *list;
			while (current->next != NULL) {
				current = current->next;
				}
			current->next = new_item;
			}
	return new_item;
}

void sort_list(struct item **list, int sort_by) {
	struct item *current = *list;
	struct item *sorted = NULL;
	struct item *next_item;

	if (*list == NULL || (*list)->next == NULL) {
		return;
		}


	while (current != NULL) {
		next_item = current->next;
		if (sorted == NULL ||
			(sort_by == BY_ADDRESS && current->addr < sorted->addr) ||
			(sort_by == BY_NAME && strcmp(current->symb_name, sorted->symb_name) < 0)) {
		current->next = sorted;
		sorted = current;
		} else {
			struct item* temp = sorted;
			while (temp->next != NULL &&
				((sort_by == BY_ADDRESS && current->addr >= temp->next->addr) ||
				(sort_by == BY_NAME && strcmp(current->symb_name, temp->next->symb_name) >= 0))) {
					temp = temp->next;
					}
			current->next = temp->next;
			temp->next = current;
			}
		current = next_item;
		}
	*list = sorted;
}

struct item *merge(struct item *left, struct item *right, int sort_by) {
	if (left == NULL) {
		return right;
		} else if (right == NULL) {
			return left;
			}

	struct item *result = NULL;
	struct item *current = NULL;

	if (sort_by == BY_NAME) {
		if (strcmp(left->symb_name, right->symb_name) <= 0) {
			result = left;
			left = left->next;
			} else {
				result = right;
				right = right->next;
				}
		} else
			if (sort_by == BY_ADDRESS) {
				if (left->addr <= right->addr) {
					result = left;
					left = left->next;
					} else {
						result = right;
						right = right->next;
						}
				}

	current = result;

	while (left && right) {
		if (sort_by == BY_NAME) {
			if (strcmp(left->symb_name, right->symb_name) <= 0) {
				current->next = left;
				left = left->next;
				} else {
					current->next = right;
					right = right->next;
					}
			} else if (sort_by == BY_ADDRESS) {
					if (left->addr <= right->addr) {
						current->next = left;
						left = left->next;
						} else {
							current->next = right;
							right = right->next;
							}
					}

		current = current->next;
		}

	if (left) {
		current->next = left;
		} else if (right) {
				current->next = right;
				}

	return result;
}

struct item *merge_sort(struct item *head, int sort_by) {
	if (head == NULL || head->next == NULL) {
		return head;
		}

	struct item *slow = head;
	struct item *fast = head->next;

	while (fast && fast->next) {
		slow = slow->next;
		fast = fast->next->next;
		}

	struct item *left = head;
	struct item *right = slow->next;
	slow->next = NULL;

	left = merge_sort(left, sort_by);
	right = merge_sort(right, sort_by);

	return merge(left, right, sort_by);
}

void sort_list_m(struct item **head, int sort_by) {
	if (*head == NULL || (*head)->next == NULL) {
		return;
		}

	*head = merge_sort(*head, sort_by);
}

int insert_after(struct item *list, const uint64_t search_addr, const char *name, uint64_t addr, char stype) {
	struct item *next_item, *new_item;
	int ret=0;
	struct item *current = (list_index[name[0]-32]!=NULL)?list_index[name[0]-32]:list;

	while (current != NULL) {
		if (current->addr == search_addr) {
			new_item = (struct item*)malloc(sizeof(struct item));
			strncpy(new_item->symb_name, name, MAX_NAME_SIZE);
			new_item->addr = addr;
			new_item->stype = stype;
			new_item->next = current->next;
			current->next = new_item;
			ret=1;
			break;
			}
		current = current->next;
		}
	assert(ret != 0);
	return ret;
}
