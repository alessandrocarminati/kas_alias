# Adding Alias to Duplicate Symbols in kallsyms

## Introduction
In the Linux kernel environment, situations often arise where symbols with
identical names are shared among core kernel components or modules. 
While this doesn't pose an issue for the kernel itself, it complicates trace
and probe operations using tools like kprobe. To address this challenge, a
solution called "kas_alias" has been introduced. Kas_alias is a tool designed
to enrich symbol names by appending meaningful suffixes derived from source
files and line numbers to create aliases for duplicate symbols.
These aliases simplify interactions with symbols during debugging and
tracing operations.

This document provides an overview of the process of adding aliases to
duplicate symbols in kallsyms, focusing on the development and integration
of the kas_alias tool into the kernel build pipeline.

## Solution Details
### Kas_Alias Overview
Kas_alias is a Python-based tool designed to scan all objects in the Linux
kernel build to maintain consistent and meaningful symbol names.
Its primary goal is to address the issue of duplicate symbols with the same
name and provide a systematic method to create aliases for these symbols.
Here's an outline of the key steps in the kas_alias process:

* Symbol Scanning: During the kernel build process, kas_alias conducts an
exhaustive search for duplicate symbols with identical names across both
the kernel core image and all module object files. These duplicate symbols
can be found within the kernel and modules due to various sources, such as
inlined functions, common library functions, and others.

* Alias Generation: For the kernel core image, kas_alias creates a new nm
data file and adds aliases for all duplicate symbols found. These aliases
are formed by appending source file and line number information to the
original symbol name. For modules, kas_alias modifies the ELF symbol table
(symtable) by adding aliases for the duplicate symbols. This ensures 
consistency and meaningful naming for symbols in both the kernel core 
image and modules.

* Alias Format: The generated aliases follow a specific format that includes
the original symbol name and additional information about their source. For
example, a symbol "device_show" might have aliases like 
```
~ # cat /proc/kallsyms | grep " device_show"
 ffffffff963cd2a0 t device_show
 ffffffff963cd2a0 t device_show@drivers_pci_pci_sysfs_c_49
 ffffffff96454b60 t device_show
 ffffffff96454b60 t device_show@drivers_virtio_virtio_c_16
 ffffffff966e1700 T device_show_ulong
 ffffffff966e1740 T device_show_int
 ffffffff966e1770 T device_show_bool
 ffffffffc04e10a0 t device_show [mmc_core]
 ffffffffc04e10a0 t device_show@drivers_mmc_core_sdio_bus_c_45  [mmc_core]
```
This format helps identify the source of each symbol, making it easier 
to work with them during debugging or tracing.

* Configuration Options: Kas_alias offers various configuration options,
allowing users to customize the alias generation process. 
Notable configuration options include the ability to process data symbols,
exclude specific patterns from alias production, and extend alias creation
to global data names.

### Special Considerations: Inclusion of "compat_binfmt_elf.c"
The inclusion of "compat_binfmt_elf.c," which directly includes "binfmt_elf.c,"
results in symbol name duplication. Addr2line, used for alias generation,
reports all functions and data declared by "binfmt_elf.c." This limitation is
acknowledged, and it is suggested that addressing this anomaly at the source
(fixing "compat_binfmt_elf.c") is a better approach than complicating the
pipeline.

### Special Considerations: Out-of-Tree Modules
The current implementation does not provide a solution for out-of-tree modules.
While these modules fall outside the tool's scope, feedback and comments
regarding this matter are welcome.

## Usage Guidelines
### Kas_Alias Command-Line Options
Kas_alias is invoked with various command-line options to customize its
behavior. 
Here are the key options:

-a ADDR2LINE_FILE: Set the addr2line executable to be used.
-b LINUX_BASE_DIR: Set the base directory of the source kernel code.
-c OBJCOPY_FILE: Set the objcopy executable to be used.
-d or --process_data: Process data symbols along with text symbols.
-e NM_FILE: Set the nm executable to be used.
-m MODULE_LIST: Set the file containing the list of the modules' object files.
-n NM_DATA_FILE: Set the vmlinux nm output file to use for the core image.
-o OUTPUT_FILE: Set the vmlinux nm output file containing aliases.
-s SEPARATOR: Set the separator character that separates the original name 
   from the addr2line data in alias symbols.
-u OBJDUMP_FILE: Set the objdump executable to be used.
-v VMLINUX_FILE: Set the vmlinux core image file.
-z {0,1,2,3,4} or --debug {0,1,2,3,4}: Set the debug level 
   (0 for quiet, 4 for verbose).

### Debugging while building the Kernel
To enable verbose execution for kas_alias, you can use 
KAS_ALIAS_DEBUG=<debug level> in the make statements during kernel build.

## Conclusion
Kas_alias is a tool for addressing the challenges of duplicate symbols with 
identical names in the Linux kernel.
By enriching symbol names with meaningful aliases, kas_alias simplifies 
interactions with symbols during trace and probe operations. 
Its integration into the kernel build pipeline enhances the overall kernel 
development process, providing more consistent and traceable symbols. 
