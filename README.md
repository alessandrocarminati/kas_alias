# kas_alias

**kas_alias** is a simple program designed to process the output of the 
`nm -n vmlinux` command in the Linux kernel and provide symbol aliasing for 
symbols with duplicate names. In the Linux kernel, symbols are not guaranteed 
to have unique names, which can cause issues when trying to probe specific 
symbols for tracing or debugging purposes.

The primary goal of **kas_alias** is to address this problem by creating 
aliases for symbols that have duplicate names but different addresses. 
By incorporating a unique suffix for each occurrence of a duplicate symbol, 
**kas_alias** enables performance engineers and developers to differentiate 
between symbols with identical names.

# Motivation

In the Linux kernel, it is not uncommon for drivers or modules related to 
similar peripherals to have symbols with the exact same name. 
While this is not a problem for the kernel's binary itself, it becomes an 
issue when attempting to trace or probe specific functions using 
infrastructure like ftrace or kprobe.

The tracing subsystem relies on the `nm -n vmlinux` output, which provides 
symbol information from the kernel's ELF binary. However, when multiple 
symbols share the same name, the standard nm output does not differentiate 
between them. This can lead to confusion and difficulty when trying to 
probe the intended symbol.

**kas_alias** addresses this challenge by extending the symbol names with 
unique suffixes during the kernel build process. By doing so, it enables 
performance engineers to effectively trace or probe symbols that would 
otherwise be indistinguishable based on name alone.


# Example

The following is an example of the modification introduced by this patch.

Without the patch, you would have:
```
ffffffff815501a0 t __pfx_device_show
ffffffff815d71b0 t __pfx_device_show
```
It is not possible to probe `__pfx_device_show` at `0xffffffff815d71b0` since 
`kallsyms_lookup_name` would only return this address.

This patch modifies the table as follows:

```
ffffffff815501a0 t __pfx_device_show
ffffffff815501a0 t __pfx_device_show__7790
ffffffff815d71b0 t __pfx_device_show
ffffffff815d71b0 t __pfx_device_show__7791
```
In this case, it is possible to probe `__pfx_device_show` at 
`0xffffffff815d71b0` by using `__pfx_device_show__7791`.

## Test log

```
~ # mount -t proc none /proc
[   16.469334] mount (52) used greatest stack depth: 14304 bytes left
~ # /bin/busybox cat /proc/kallsyms | /bin/busybox grep __pfx_device_show
ffffffffb2b501a0 t __pfx_device_show
ffffffffb2b501a0 t __pfx_device_show__7790
ffffffffb2bd71b0 t __pfx_device_show
ffffffffb2bd71b0 t __pfx_device_show__7791
ffffffffb2e481f0 T __pfx_device_show_ulong
ffffffffb2e48230 T __pfx_device_show_int
ffffffffb2e48260 T __pfx_device_show_bool
~ # mount -t sysfs none /sys
~ # mount -t tracefs none /sys/kernel/tracing/
~ # /bin/busybox echo "p:kprobes/evnt1 __pfx_device_show__7791" >/sys/kernel/tracing/kprobe_events  
~ # /bin/busybox cat /sys/kernel/tracing/kprobe_events
p:kprobes/evnt1 __pfx_device_show__7791
~ # 
```

# Patch the kernel

Here is a proposal to patch the kernel build process and integrate 
the utility within it. In the `patch` directory, there is a 
ready-to-use patch for the current kernel version `6.4`.
