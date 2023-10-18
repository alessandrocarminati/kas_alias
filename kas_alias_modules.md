# Notes for kas_alias Version 6, that includes module aliases support.

## Strategy

Actions need to be performed before invoking `modpost`. 
`modpost` is a utility that carries out various tasks on an object file.
One of its functions is to provide a `.mod.c` file, which is built and
linked to the original module's object file. 
This additional step creates extra sections in the ELF object module.

What's important to note is that when `modpost` commences its operations,
all the objects are already in a completed state from a textual perspective.
Furthermore, during the linking of the `vmlinux` kernel image, specifically 
when `scripts/link-vmlinux.sh` is invoked, all the objects are ready and 
linked.

For this reason, `kas_alias` merely needs to extend the initial scan to 
include the module object files found in `modules.order`. 
Its purpose is to gather all symbols and perform the duplicate search. 
`kas_alias` can continue to operate in the same manner it has done for 
`vmlinux`. 
However, after that stage, it needs to add aliases to the modules, which
do not utilize `nm`.

Interestingly, within any given module, there is no data structure that 
directly contains symbol names. 
So, you might wonder where the symbol names are stored within a module.

Surprisingly, symbol names are stored where one would logically expect 
to find them within an ELF object: in the symbol table, which is labeled
as `.symtab`. 
Adding a symbol to the object is as straightforward as executing the 
following command:

```shell
~ # objcopy --add-symbol alias=<section>:0x0000000000000xxx,<flag> module.o moduleWaliases.o
```
Use:
* section=`.text`,   flag=`global` for `T` symbols,
* section=`.text`,   flag=`local`  for `t` symbols,
* section=`.rodata`, flag=`global` for `D` symbols,
* section=`.rodata`, flag=`local`  for `d` symbols,
possibly others.

## Pilot test
After having a kernel successfully built, I picked a module 
`fs/efivarfs/efivarfs.ko` and performed the following operations to
allow an alias for `efivarfs_file_read`:

```
~ # rm fs/efivarfs/efivarfs.ko fs/efivarfs/efivarfs.mod.o
~ # objcopy --add-symbol efivarfs_file_read@alias=.text:0x0000000000000620,local fs/efivarfs/efivarfs.o fs/efivarfs/efivarfs2.o
~ # make
```
running the kernel just built and inserting the module,
this is the situation:

```
~ # insmod efivarfs.ko 
[   47.748932] insmod (94) used greatest stack depth: 12904 bytes left
~ # lsmod
Module                  Size  Used by    Not tainted
efivarfs               24576  0 
~ # cat /proc/kallsyms | grep @
ffffffffc02bc620 t efivarfs_file_read@alias	[efivarfs]
~ # cat /proc/kallsyms | grep efivarfs_file_operations
ffffffffc02bc620 t efivarfs_file_read@alias	[efivarfs]
ffffffffc02c2620 t efivarfs_file_read	[efivarfs]
~ # 
```
