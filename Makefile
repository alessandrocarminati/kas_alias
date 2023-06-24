#CFLAGS=-pg -g


all: main


parse_linker_log.o: parse_linker_log.c parse_linker_log.h
	gcc ${CFLAGS} -c -o parse_linker_log.o parse_linker_log.c

duplicates_list.o: duplicates_list.c duplicates_list.h
	 gcc ${CFLAGS} -c -o duplicates_list.o duplicates_list.c

item_list.o: item_list.c item_list.h
	gcc ${CFLAGS} -c -o item_list.o item_list.c

main:	item_list.o duplicates_list.o parse_linker_log.o main.c
	gcc -o main ${CFLAGS} duplicates_list.o item_list.o parse_linker_log.o main.c

clean:
	rm *.o
	rm main
