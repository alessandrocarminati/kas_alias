#ifndef PARSE_LINKER_LOG_H
#define PARSE_LINKER_LOG_H

#include <stdint.h>

#define MAX_NAME_SIZE 256
#define TEXT_NEEDED_REGEXP "^[ \t]*([^ ]+)[ \t]+0x([0-9a-f]+)[ \t]+0x([0-9a-f]+)[ \t]+(.*)$"

struct linker_object {
    char type[MAX_NAME_SIZE];
    uint64_t address;
    uint32_t size;
    char filename[MAX_NAME_SIZE];
    struct linker_object* next;
};

struct linker_object* parseLinkerObjects(const char* filename);
const char *addr2filename(struct linker_object *ldo_data, uint64_t address);

#endif
