#CFLAGS=-pg -g


all: main


duplicates_list.o: duplicates_list.c duplicates_list.h
	 gcc ${CFLAGS} -c -o duplicates_list.o duplicates_list.c

item_list.o: item_list.c item_list.h
	gcc ${CFLAGS} -c -o item_list.o item_list.c

main:	item_list.o duplicates_list.o main.c
	gcc -o main ${CFLAGS} duplicates_list.o item_list.o main.c

clean:
	rm *.o
	rm main
