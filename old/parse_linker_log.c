#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <stdint.h>
#include <string.h>

#include "parse_linker_log.h"

struct linker_object* parseLinkerObjects(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        printf("Failed to open file: %s\n", filename);
        return NULL;
    }

    struct linker_object* list = NULL;
    regex_t regex;
    int ret = regcomp(&regex, TEXT_NEEDED_REGEXP, REG_EXTENDED);
    if (ret != 0) {
        printf("Failed to compile regex pattern\n");
        fclose(file);
        return NULL;
    }

    char line[MAX_NAME_SIZE * 4];  // Assume each line is no longer than MAX_NAME_SIZE * 4
    while (fgets(line, sizeof(line), file) != NULL) {
        // Remove the trailing newline character
        line[strcspn(line, "\n")] = '\0';

        // Execute the regular expression matching
        regmatch_t matches[5];
        if (regexec(&regex, line, 5, matches, 0) == 0) {
            // Create a new linker_object
            struct linker_object* new_object = (struct linker_object*)malloc(sizeof(struct linker_object));

            // Extract captured groups and assign values
            // Group 1: Type
            int type_len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(new_object->type, line + matches[1].rm_so, type_len);
            new_object->type[type_len] = '\0';

            // Group 2: Address
            int address_len = matches[2].rm_eo - matches[2].rm_so;
            char* address_str = (char*)malloc((address_len + 1) * sizeof(char));
            strncpy(address_str, line + matches[2].rm_so, address_len);
            address_str[address_len] = '\0';
            new_object->address = strtoull(address_str, NULL, 16);
            free(address_str);

            // Group 3: Size
            int size_len = matches[3].rm_eo - matches[3].rm_so;
            char* size_str = (char*)malloc((size_len + 1) * sizeof(char));
            strncpy(size_str, line + matches[3].rm_so, size_len);
            size_str[size_len] = '\0';
            new_object->size = strtoul(size_str, NULL, 16);
            free(size_str);

            // Group 4: Filename
            int filename_len = matches[4].rm_eo - matches[4].rm_so;
            strncpy(new_object->filename, line + matches[4].rm_so, filename_len);
            new_object->filename[filename_len] = '\0';

            // Add the new object to the list
            new_object->next = list;
            list = new_object;
        }
    }

    // Free the compiled regular expression
    regfree(&regex);

    // Close the file
    fclose(file);

    return list;
}
const char *addr2filename(struct linker_object *ldo_data, uint64_t address){
	char *ret="";
	struct linker_object *ldo_iterator=ldo_data;

	while (ldo_iterator!=NULL){
		if ( (address>=ldo_iterator->address) && (address<=ldo_iterator->address+ldo_iterator->size) ) {
			ret=ldo_iterator->filename;
			break;
			}
		ldo_iterator=ldo_iterator->next;
		}
	return ret;
}
