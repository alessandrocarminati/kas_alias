#CFLAGS= -pg -g -Wall -std=gnu89


all: main


duplicates_list.o: duplicates_list.c duplicates_list.h
	 gcc ${CFLAGS} -c -o duplicates_list.o duplicates_list.c

item_list.o: item_list.c item_list.h
	gcc ${CFLAGS} -c -o item_list.o item_list.c

main:	item_list.o duplicates_list.o kas_alias.c malloc_moc.so
	gcc -o main ${CFLAGS} duplicates_list.o item_list.o kas_alias.c

malloc_moc.so: malloc_moc.c
	gcc -shared -fPIC -D_GNU_SOURCE malloc_moc.c -o malloc_moc.so -ldl

clean:
	rm -f *.o
	rm -f *.so
	rm -f main
