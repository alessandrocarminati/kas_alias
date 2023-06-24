#ifndef ITEM_LIST_H
#define ITEM_LIST_H
#include <stdint.h>

#define MAX_NAME_SIZE 256
#define BY_ADDRESS 1
#define BY_NAME 2

struct item {
	char		symb_name[MAX_NAME_SIZE];
	uint64_t	addr;
	char		stype;
	struct item 	*next;
};

struct item *addItem(struct item **list, const char *name, char stype, uint64_t addr);
void sortList(struct item **list, int sort_by);
struct item* merge(struct item* left, struct item* right, int sortCriteria);
struct item* mergeSort(struct item* head, int sortCriteria);
void sortList_m(struct item** head, int sortCriteria);
int insert_after(struct item *list, const uint64_t search_addr, const char *name, uint64_t addr, char stype);
#endif
