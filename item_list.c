// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "item_list.h"

#define CHECK_ORDER_BY_ADDRESS(sort_by, current, temp, op) \
	((sort_by) == BY_ADDRESS && (current)->addr op (temp)->addr)
#define CHECK_ORDER_BY_NAME(sort_by, current, temp, op) \
	((sort_by) == BY_NAME && strcmp((current)->symb_name, (temp)->symb_name) op 0)

struct item *list_index[96] = {0};

void build_index(struct item *list)
{
	char current_first_letter = ' ';
	struct item *current = list;

	while (current) {
		if (current->symb_name[0] != current_first_letter) {
			current_first_letter = current->symb_name[0];
			list_index[current_first_letter - 32] = current;
		}
		current = current->next;
	}
}

struct item *add_item(struct item **list, const char *name, char stype, uint64_t addr)
{
	struct item *new_item;
	struct item *current;

	new_item = malloc(sizeof(struct item));
	if (!new_item)
		return NULL;

	strncpy(new_item->symb_name, name, MAX_NAME_SIZE);
	new_item->symb_name[MAX_NAME_SIZE - 1] = '\0';
	new_item->addr = addr;
	new_item->stype = stype;
	new_item->next = NULL;

	if (!(*list)) {
		*list = new_item;
	} else {
		current = *list;
		while (current->next)
			current = current->next;

		current->next = new_item;
	}
	return new_item;
}

void sort_list(struct item **list, int sort_by)
{
	struct item *current = *list;
	struct item *sorted = NULL;
	struct item *next_item;
	struct item *temp;

	if (!(*list) || !((*list)->next))
		return;

	while (current) {
		next_item = current->next;
		if (!sorted ||
		    (CHECK_ORDER_BY_ADDRESS(sort_by, current, sorted, <) ||
		    CHECK_ORDER_BY_NAME(sort_by, current, sorted, >=))) {
			current->next = sorted;
			sorted = current;
		} else {
			temp = sorted;
			while (temp->next &&
			       (CHECK_ORDER_BY_ADDRESS(sort_by, current, temp->next, >=) ||
			       CHECK_ORDER_BY_NAME(sort_by, current, temp->next, >=)))
				temp = temp->next;

			current->next = temp->next;
			temp->next = current;
		}
		current = next_item;
	}

	*list = sorted;
}

struct item *merge(struct item *left, struct item *right, int sort_by)
{
	struct item *current = NULL;
	struct item *result = NULL;

	if (!left)
		return right;
	if (!right)
		return left;

	if (sort_by == BY_NAME) {
		if (strcmp(left->symb_name, right->symb_name) <= 0) {
			result = left;
			left = left->next;
		} else {
			result = right;
			right = right->next;
		}
	} else {
		if (sort_by == BY_ADDRESS) {
			if (left->addr <= right->addr) {
				result = left;
				left = left->next;
			} else {
				result = right;
				right = right->next;
			}
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
		} else {
			if (sort_by == BY_ADDRESS) {
				if (left->addr <= right->addr) {
					current->next = left;
					left = left->next;
				} else {
					current->next = right;
					right = right->next;
				}
			}
		}

		current = current->next;
	}

	if (left) {
		current->next = left;
	} else {
		if (right)
			current->next = right;
	}

	return result;
}

struct item *merge_sort(struct item *head, int sort_by)
{
	struct item *right;
	struct item *slow;
	struct item *fast;
	struct item *left;

	if (!head || !head->next)
		return head;

	slow = head;
	fast = head->next;

	while (fast && fast->next) {
		slow = slow->next;
		fast = fast->next->next;
	}

	left = head;
	right = slow->next;
	slow->next = NULL;

	left = merge_sort(left, sort_by);
	right = merge_sort(right, sort_by);

	return merge(left, right, sort_by);
}

void sort_list_m(struct item **head, int sort_by)
{
	if (!(*head) || !((*head)->next))
		return;

	*head = merge_sort(*head, sort_by);
}

int insert_after(struct item *list, const uint64_t search_addr,
		 const char *name, uint64_t addr, char stype)
{
	struct item *new_item;
	struct item *current;
	int ret = 0;

	current = (list_index[name[0] - 32]) ? list_index[name[0] - 32] : list;
	while (current) {
		if (current->addr == search_addr) {
			new_item = malloc(sizeof(struct item));
			if (!new_item)
				return ret;
			strncpy(new_item->symb_name, name, MAX_NAME_SIZE);
			new_item->symb_name[MAX_NAME_SIZE - 1] = '\0';
			new_item->addr = addr;
			new_item->stype = stype;
			new_item->next = current->next;
			current->next = new_item;
			ret = 1;
			break;
		}
		current = current->next;
	}
	return ret;
}

void free_items(struct item **head)
{
	struct item *app, *item_iterator = *head;

	while (item_iterator) {
		app = item_iterator;
		item_iterator = item_iterator->next;
		free(app);
	}
	*head = NULL;
}
