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

# Regex representing symbols that needs no alias
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
        "^\\.LC[0-9]+$"
        "^__UNIQUE_ID___.*$"
        "^symbols\\.[0-9]+$"
        ]

class SeparatorType:
    def __call__(self, separator):
        if len(separator) != 1:
            raise argparse.ArgumentTypeError("Separator must be a single character")
        return separator

class Addr2LineError(Exception):
    pass

Line = namedtuple('Line', ['address', 'type', 'name'])

# Parses a given nm output and returns the symbol list along with a hash of symbol occurrences
def parse_nm_lines(lines, name_occurrences=None):

    if name_occurrences is None:
        name_occurrences = {}

    symbol_list = []

    for line in lines:
        fields = line.strip().split()

        if len(fields) >= 3:
            address, type, name = fields[0], fields[1], ' '.join(fields[2:])
            symbol_list.append(Line(address, type, name))
            name_occurrences[name] = name_occurrences.get(name, 0) + 1

    return symbol_list, name_occurrences

# Initializes an addr2line server process for the given ELF object
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

# Queries a specific address using the active addr2line process
def addr2line_fetch_address(addr2line_process, address):
    try:
        addr2line_process.stdin.write(address + '\n')
        addr2line_process.stdin.flush()
        addr2line_process.stdout.readline().strip()
        output = addr2line_process.stdout.readline().strip()

        return os.path.normpath(output)
    except Exception as e:
        raise Addr2LineError(f"Error communicating with addr2line: {str(e)}")

# Determines whether a duplicate item requires an alias or not
def process_line(obj, process_data_sym):
    if process_data_sym:
        return not (any(re.match(regex, obj.name) for regex in regex_filter))
    else:
        return (obj.type in {"T", "t"}) and (not (any(re.match(regex, obj.name) for regex in regex_filter)))

# Reads a text file and retrieves its content
def fetch_file_lines(filename):
    try:
        with open(filename, 'r') as file:
#            lines = file.readlines()
            lines = [line.strip() for line in file.readlines()]
        return lines
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filename}")

# Runs the nm command on a specified file and returns its output as a list of strings
def do_nm(filename, nm_executable):
    try:
        nm_output = subprocess.check_output([nm_executable, '-n', filename], universal_newlines=True, stderr=subprocess.STDOUT).splitlines()
        return nm_output
    except subprocess.CalledProcessError as e:
        print(f"Error executing 'nm' command: {e.output}")
        print(f"pwd={os.getcwd()}")
        print(f"filename={filename}")
        raise SystemExit("Script terminated due to an error")

# Accepts a Line object and a decoration string, then generates an argument to be used with objcopy for
# adding an alias to the module's object file
def make_objcpy_arg(obj, decoration, elf_section_names):
#    section = elf_section_names[".text"] if obj.type.upper() == "T" else (elf_section_names[".data"] if obj.type.upper() == "D" else (elf_section_names[".rodata"] if obj.type.upper() == "R" else ".bss"))
    section = (
        elf_section_names[".text"] if obj.type.upper() == "T" else (
            elf_section_names[".data"] if obj.type.upper() == "D" else (
                elf_section_names[".rodata"] if obj.type.upper() == "R" else ".bss"
            )
        )
    )
    flag = "global" if obj.type.isupper() else "local"

    return f"--add-symbol {obj.name + decoration}={section}:0x{obj.address},{flag} "

# Adds aliases to a given module's object file by executing objcopy
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

# Generates symbol decoration by querying addr2line
def generate_decoration(obj, config, addr2line_process):
    output = addr2line_fetch_address(addr2line_process, obj.address)
    decoration = config.separator + "".join(
        "_" if not c.isalnum() else c for c in output.replace(config.linux_base_dir, "")
    )
    # The addr2line can emit the special string "?:??" when addr2line can not find the
    # specified address in the DWARF section that after normalization it becomes "____".
    # In such cases, emitting an alias wouldn't make sense, so it is skipped.
    if decoration != config.separator + "____":
       return decoration
    return ""

# retrive the meaningful section names from the object header
def get_section_names(objdump_executable, file_to_operate):
    try:
        output = subprocess.check_output([objdump_executable, '-h', file_to_operate], universal_newlines=True)

        section_names = []
        lines = output.strip().splitlines()
        section_name_pattern = re.compile(r'^\s*\d+')
        for line in lines:
            if section_name_pattern.match(line):
                parts = line.split()
                if len(parts) >= 2:
                    section_name = parts[1]
                    section_names.append(section_name)

        best_matches = [".text", ".rodata", ".data", ".bss"]
        result = {}

        for match in best_matches:
            for section_name in section_names:
                if section_name == match:
                    result[match] = section_name
                    break
                if section_name.startswith(match + "."):
                    result[match] = section_name
                    break

        return result

    except subprocess.CalledProcessError as e:
        print(f"Error executing objdump: {e}")
        return {}

# Creates a new module object file with added aliases in the ELF .symtab
def produce_output_modules(config, symbol_list, name_occurrences, module_file_name, addr2line_process):
    objcopy_args = "";
    elf_section_names = get_section_names(config.objdump_file, module_file_name)
    for obj in symbol_list:
        if (name_occurrences[obj.name] > 1) and process_line(obj, config.process_data_sym):
            decoration = generate_decoration(obj, config, addr2line_process)
            if decoration != "":
                objcopy_args = objcopy_args + make_objcpy_arg(obj, decoration, elf_section_names)

    print(f"kas_alias: {config.objcopy_file} {objcopy_args} {module_file_name}.bak {module_file_name}")
    execute_objcopy(config.objcopy_file, objcopy_args, module_file_name)

# Generates a new file containing nm data for vmlinux with the added aliases
def produce_output_vmlinux(config, symbol_list, name_occurrences, addr2line_process):
    with open(config.output_file, 'w') as output_file:
        for obj in symbol_list:
            output_file.write(f"{obj.address} {obj.type} {obj.name}\n")
            if (name_occurrences[obj.name] > 1) and process_line(obj, config.process_data_sym):
                decoration = generate_decoration(obj, config, addr2line_process)
                if decoration != "":
                    output_file.write(f"{obj.address} {obj.type} {obj.name + decoration}\n")

# Copies a file using the sell
def copy_file(source, destination):
    copy_command = f"cp {source} {destination}"

    try:
        subprocess.check_output(copy_command, shell=True)
    except subprocess.CalledProcessError:
        print(f"Error copying {source_file} to {destination_file}.")
        raise SystemExit("Script terminated due to an error")

if __name__ == "__main__":
    # Handles command-line arguments and generates a config object
    parser = argparse.ArgumentParser(description='Add alias to multiple occurring symbols name in kallsyms')
    parser.add_argument('-a', "--addr2line", dest="addr2line_file", required=True)
    parser.add_argument('-b', "--basedir", dest="linux_base_dir", required=True)
    parser.add_argument('-c', "--objcopy", dest="objcopy_file", required=True)
    parser.add_argument('-d', "--process_data", dest="process_data_sym", required=False, action='store_true')
    parser.add_argument('-e', "--nm", dest="nm_file", required=True)
    parser.add_argument('-m', "--modules_list", dest="module_list", required=True)
    parser.add_argument('-n', "--nmdata", dest="nm_data_file", required=True)
    parser.add_argument('-o', "--outfile", dest="output_file", required=True)
    parser.add_argument('-s', "--separator", dest="separator", required=False, default="@", type=SeparatorType())
    parser.add_argument('-u', "--objdump", dest="objdump_file", required=True)
    parser.add_argument('-v', "--vmlinux", dest="vmlinux_file", required=True)
    config = parser.parse_args()

    try:
        print("kas_alias: Start processing")

        # Determine kernel source code base directory
        config.linux_base_dir = os.path.normpath(os.getcwd() + "/" + config.linux_base_dir) + "/"

        print("kas_alias: Process nm data from vmlinux")
        # Process nm data from vmlinux
        vmlinux_nm_lines = fetch_file_lines(config.nm_data_file)
        vmlinux_symbol_list, name_occurrences = parse_nm_lines(vmlinux_nm_lines)

        print("kas_alias: Process nm data for modules")
        # Process nm data for modules
        module_list = fetch_file_lines(config.module_list)
        module_symbol_list = {}
        for module in module_list:
            module_nm_lines = do_nm(module, config.nm_file)
            module_symbol_list[module], name_occurrences = parse_nm_lines(module_nm_lines, name_occurrences)

        print("kas_alias: Produce file for vmlinux")
        # Produce file for vmlinux
        addr2line_process = start_addr2line_process(config.vmlinux_file, config.addr2line_file)
        produce_output_vmlinux(config, vmlinux_symbol_list, name_occurrences, addr2line_process)
        addr2line_process.stdin.close()
        addr2line_process.stdout.close()
        addr2line_process.stderr.close()
        addr2line_process.wait()

        # link-vmlinux.sh calls this two times: Avoid running kas_alias twice for efficiency and prevent duplicate aliases
        #  in module processing by checking the last letter of the nm data file
        if config.vmlinux_file and config.vmlinux_file[-1] == '2':
            print("kas_alias: Add aliases to module files")
            # Add aliases to module files
            for module in module_list:
                addr2line_process = start_addr2line_process(module, config.addr2line_file)
                produce_output_modules(config, module_symbol_list[module], name_occurrences, module, addr2line_process)
                addr2line_process.stdin.close()
                addr2line_process.stdout.close()
                addr2line_process.stderr.close()
                addr2line_process.wait()
        else:
            print("kas_alias: Skip module processing if pass is different from second")


    except Addr2LineError as e:
        print(f"An error occurred in addr2line: {str(e)}")
        raise SystemExit("Script terminated due to an error")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        raise SystemExit("Script terminated due to an error")
