#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2023 Red Hat, Inc. Alessandro Carminati <alessandro.carminati@gmail.com>
#
# kas_alias: Adds alias to duplicate symbols in the kallsyms output.

import subprocess
import sys
import os
import argparse
import re
from collections import namedtuple

regex_filter = [
        "^__compound_literal\\.[0-9]+$",
        "^__[wm]*key\\.[0-9]+$",
        "^_*TRACE_SYSTEM.*$",
        "^__already_done\\.[0-9]+$",
        "^__msg\\.[0-9]+$",
        "^__func__\\.[0-9]+$",
        "^CSWTCH\\.[0-9]+$",
        "^_rs\\.[0-9]+$",
        "^___tp_str\\.[0-9]+$",
        "^__flags\\.[0-9]+$",
        "^___done\\.[0-9]+$",
        "^__print_once\\.[0-9]+$",
        "^___once_key\\.[0-9]+$",
        "^__pfx_.*$",
        "^__cfi_.*$"
        ]

class SeparatorType:
    def __call__(self, separator):
        if len(separator) != 1:
            raise argparse.ArgumentTypeError("Separator must be a single character")
        return separator

class Addr2LineError(Exception):
    pass

# it takes an nm data and returns symbol_list and name_occurences
Line = namedtuple('Line', ['address', 'type', 'name'])

def parse_nm_lines(lines, symbol_list=None, name_occurrences=None):
    if symbol_list is None:
        symbol_list = []
    if name_occurrences is None:
        name_occurrences = {}

    for line in lines:
        fields = line.strip().split()

        if len(fields) >= 3:
            address, type, name = fields[0], fields[1], ' '.join(fields[2:])
            symbol_list.append(Line(address, type, name))
            name_occurrences[name] = name_occurrences.get(name, 0) + 1

    return symbol_list, name_occurrences

def start_addr2line_process(binary_file, addr2line_file):
    try:
        addr2line_process = subprocess.Popen([addr2line_file, '-fe', binary_file],
                                             stdin=subprocess.PIPE,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE,
                                             text=True)
        return addr2line_process
    except Exception as e:
         raise Addr2LineError(f"Error starting addr2line process: {str(e)}")

def addr2line_fetch_address(addr2line_process, address):
    try:
        addr2line_process.stdin.write(address + '\n')
        addr2line_process.stdin.flush()
        addr2line_process.stdout.readline().strip()
        output = addr2line_process.stdout.readline().strip()

        return os.path.normpath(output)
    except Exception as e:
        raise Addr2LineError(f"Error communicating with addr2line: {str(e)}")

def process_line(obj, process_data_sym):
    if process_data_sym:
        return not (any(re.match(regex, obj.name) for regex in regex_filter))
    else:
        return (obj.type in {"T", "t"}) and (not (any(re.match(regex, obj.name) for regex in regex_filter)))

def fetch_file_lines(filename):
    try:
        with open(filename, 'r') as file:
            lines = file.readlines()
        return lines
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filename}")

# Executes nm on a given file an returns its output as string list
def do_nm(filename, nm_executable):
    try:
        nm_output = subprocess.check_output([nm_executable, '-n', filename], universal_newlines=True, stderr=subprocess.STDOUT).splitlines()
        return nm_output
    except subprocess.CalledProcessError as e:
        print(f"Error executing 'nm' command: {e.output}")
        return []

# --------------------> should I need to close file?
def produce_output_vmlinux(config, symbol_list, name_occurrences, addr2line_process):
    with open(config.output_file, 'w') as output_file:
        for obj in symbol_list:
            output_file.write(f"{obj.address} {obj.type} {obj.name}\n")
            if (name_occurrences[obj.name] > 1) and process_line(obj, config.process_data_sym):
                output = addr2line_fetch_address(addr2line_process, obj.address)
                decoration = config.separator + "".join(
                    "_" if not c.isalnum() else c for c in output.replace(config.linux_base_dir, "")
                )
                # The addr2line can emit the special string "?:??" when addr2line can not find the
                # specified address in the DWARF section that after normalization it becomes "____".
                # In such cases, emitting an alias wouldn't make sense, so it is skipped.
                if decoration != config.separator + "____":
                    output_file.write(f"{obj.address} {obj.type} {obj.name + decoration}\n")

# takes a line object and a decoration string and produces an argument to use with objcopy to add an alias to the module object file
def make_objcpy_arg(obj, decoration):
    section = ".text" if obj.type.upper() == "T" else (".rodata" if obj.type.upper() == "D" else ".bss")
    flag = "global" if obj.type.isupper() else "local"

    return f"--add-symbol {obj.name + decoration}={section}:{obj.address},{flag} "

def execute_objcopy(objcopy_executable, objcopy_args, object_file):
    # Rename the original object file by adding a suffix
    backup_file = object_file + '.bak'
    os.rename(object_file, backup_file)

    full_command = f"{objcopy_executable} {objcopy_args} {backup_file} {object_file}"

    try:
        subprocess.run(full_command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing objcopy: {e}")
        os.rename(backup_file, object_file)
        raise SystemExit("Script terminated due to an error")

def produce_output_modules(config, symbol_list, name_occurrences, module_file_name, addr2line_process):
    for obj in symbol_list:
        if (name_occurrences[obj.name] > 1) and process_line(obj, config.process_data_sym):
            output = addr2line_fetch_address(addr2line_process, obj.address)
            decoration = config.separator + "".join(
                "_" if not c.isalnum() else c for c in output.replace(config.linux_base_dir, "")
            )
            # The addr2line can emit the special string "?:??" when addr2line can not find the
            # specified address in the DWARF section that after normalization it becomes "____".
            # In such cases, emitting an alias wouldn't make sense, so it is skipped.
            if decoration != config.separator + "____":
                objcopy_args = objcopy_args + make_objcpy_arg(obj, decoration)

    execute_objcopy(config.objcopy_file, objcopy_args, module_file_name)

if __name__ == "__main__":
    # Deal with commandline
    parser = argparse.ArgumentParser(description='Add alias to multiple occurring symbols name in kallsyms')
    parser.add_argument('-a', "--addr2line", dest="addr2line_file", required=True)
    parser.add_argument('-n', "--nm", dest="nm_file", required=True)
    parser.add_argument('-c', "--objcopy", dest="objcopy_file", required=True)
    parser.add_argument('-v', "--vmlinux", dest="vmlinux_file", required=True)
    parser.add_argument('-o', "--outfile", dest="output_file", required=True)
    parser.add_argument('-n', "--nmdata", dest="nm_data_file", required=True)
    parser.add_argument('-b', "--basedir", dest="linux_base_dir", required=True)
    parser.add_argument('-m', "--modules_list", dest="module_list", required=True)
    parser.add_argument('-s', "--separator", dest="separator", required=False, default="@", type=SeparatorType())
    parser.add_argument('-d', "--process_data", dest="process_data_sym", required=False, action='store_true')
    config = parser.parse_args()

    try:
        # Determine source base directory
        config.linux_base_dir = os.path.normpath(os.getcwd() + "/" + config.linux_base_dir) + "/"

        # Process nm data from vmlinux
        vmlinux_nm_lines = fetch_file_lines(config.nm_data_file)
        vmlinux_symbol_list, name_occurrences = parse_nm_lines(vmlinux_nm_lines)

        # Process nm data for modules
        module_list = fetch_flie_lines(config.module_list)
        for module in module_list:
            module_nm_lines = do_nm(module, config.nm_file)
            module_symbol_list[module], name_occurrences = parse_nm_lines(module_nm_lines, name_occurrences)

        # Start addr2line resolver
        addr2line_process = start_addr2line_process(config.vmlinux_file, config.addr2line_file)

        # Produce data for vmlinux
        produce_output_vmlinux(config, vmlinux_symbol_list, name_occurrences, addr2line_process)

	# Add aliases to module files
        for module in module_list:
            produce_output_modules(config, module_symbol_list[module], name_occurrences, addr2line_process)

	# Shutdown addr2line process
        addr2line_process.stdin.close()
        addr2line_process.stdout.close()
        addr2line_process.stderr.close()
        addr2line_process.wait()

    except Addr2LineError as e:
        print(f"An error occurred in addr2line: {str(e)}")
        raise SystemExit("Script terminated due to an error")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        raise SystemExit("Script terminated due to an error")
