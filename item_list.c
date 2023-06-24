#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "item_list.h"

struct item *addItem(struct item **list, const char *name, char stype, uint64_t addr) {
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

void sortList(struct item **list, int sort_by) {
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

struct item *merge(struct item *left, struct item *right, int sortCriteria) {
	if (left == NULL) {
		return right;
		} else if (right == NULL) {
			return left;
			}

	struct item *result = NULL;
	struct item *current = NULL;

	if (sortCriteria == BY_NAME) {
		if (strcmp(left->symb_name, right->symb_name) <= 0) {
			result = left;
			left = left->next;
			} else {
				result = right;
				right = right->next;
				}
		} else
			if (sortCriteria == BY_ADDRESS) {
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
		if (sortCriteria == BY_NAME) {
			if (strcmp(left->symb_name, right->symb_name) <= 0) {
				current->next = left;
				left = left->next;
				} else {
					current->next = right;
					right = right->next;
					}
			} else if (sortCriteria == BY_ADDRESS) {
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

struct item *mergeSort(struct item *head, int sortCriteria) {
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

	left = mergeSort(left, sortCriteria);
	right = mergeSort(right, sortCriteria);

	return merge(left, right, sortCriteria);
}

void sortList_m(struct item **head, int sortCriteria) {
	if (*head == NULL || (*head)->next == NULL) {
		return;
		}

	*head = mergeSort(*head, sortCriteria);
}

int insert_after(struct item *list, const uint64_t search_addr, const char *name, uint64_t addr, char stype) {
	struct item *current = list;
	struct item *next_item, *new_item;
	int ret=0;

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
	return ret;
}
