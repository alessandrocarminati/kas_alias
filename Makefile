

all: main


parse_linker_log.o: parse_linker_log.c parse_linker_log.h
	gcc -c -o parse_linker_log.o parse_linker_log.c

duplicates_list.o: duplicates_list.c duplicates_list.h
	 gcc -c -o duplicates_list.o duplicates_list.c

item_list.o: item_list.c item_list.h
	gcc -c -o item_list.o item_list.c

main:	item_list.o duplicates_list.o parse_linker_log.o main.c
	gcc -o main duplicates_list.o item_list.o parse_linker_log.o main.c

