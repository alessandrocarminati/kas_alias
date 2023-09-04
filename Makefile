#CFLAGS= -pg -g -Wall -std=gnu89
#CFLAGS= -Wall -std=gnu89 -DCONFIG_KALLSYMS_ALIAS_DATA -DCONFIG_KALLSYMS_ALIAS_DATA
CFLAGS= -Wall -g -std=gnu89


all: main


#duplicates_list.o: duplicates_list.c duplicates_list.h
#	 gcc ${CFLAGS} -c -o duplicates_list.o duplicates_list.c

conf.o: conf.c conf.h
	gcc ${CFLAGS} -c -o conf.o conf.c

item_list.o: item_list.c item_list.h
	gcc ${CFLAGS} -c -o item_list.o item_list.c

a2l.o: a2l.c a2l.h
	gcc ${CFLAGS} -c -o a2l.o a2l.c

main:	item_list.o a2l.o conf.o kas_alias.c
	gcc -o main ${CFLAGS} conf.o a2l.o item_list.o kas_alias.c

clean:
	rm -f *.o
	rm -f *.so
	rm -f main
