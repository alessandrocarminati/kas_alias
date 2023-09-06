#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2019-2023 Red Hat, Inc. Alessandro Carminati <alessandro.carminati@gmail.com>
#
# kas_alias: Adds alias to duplicate symbols in the kallsyms output
#
# For further information, see:
# Documentation/..

import subprocess
import sys
import os
import argparse
from collections import namedtuple

Line = namedtuple('Line', ['address', 'type', 'name'])

def parse_file(filename):
    symbol_list = []
    name_occurrences = {}

    with open(filename, 'r') as file:
        for line in file:
            fields = line.strip().split()

            if len(fields) >= 3:
                address, type, name = fields[0], fields[1], ' '.join(fields[2:])
                symbol_list.append(Line(address, type, name))
                name_occurrences[name] = name_occurrences.get(name, 0) + 1

    return symbol_list, name_occurrences

def find_duplicate(symbol_list, name_occurrences):
    name_to_lines = {}
    duplicate_lines = []

    for line in symbol_list:
        if line.name in name_to_lines:
            first_occurrence = name_to_lines[line.name]
            duplicate_lines.extend([first_occurrence, line])
        else:
            name_to_lines[line.name] = line

    return duplicate_lines

def start_addr2line_process(binary_file, addr2line_file):
    try:
        addr2line_process = subprocess.Popen([addr2line_file, '-fe', binary_file],
                                             stdin=subprocess.PIPE,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE,
                                             text=True)
        return addr2line_process
    except Exception as e:
        print(f"Error starting addr2line process: {str(e)}")
        return None

def send_line_to_addr2line(addr2line_process, line):
    try:
        addr2line_process.stdin.write(line + '\n')
        addr2line_process.stdin.flush()
    except Exception as e:
        print(f"Error sending data to addr2line: {str(e)}")

def fetch_line_from_addr2line(addr2line_process):
    try:
        line = addr2line_process.stdout.readline().strip()
        return line
    except Exception as e:
        print(f"Error fetching data from addr2line: {str(e)}")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Add alias to multiple occurring symbols name in kallsyms')
    parser.add_argument('-a', "--addr2line", dest="addr2line_file", required=True)
    parser.add_argument('-v', "--vmlinux", dest="vmlinux_file", required=True)
    parser.add_argument('-o', "--outfile", dest="output_file", required=True)
    parser.add_argument('-n', "--nmdata", dest="nm_data_file", required=True)
    config = parser.parse_args()

    try:
        config.linux_base_dir = os.path.dirname(config.vmlinux_file)
        symbol_list, name_occurrences = parse_file(config.nm_data_file)
        addr2line_process = start_addr2line_process(config.vmlinux_file, config.addr2line_file)

        with open(config.output_file, 'w') as file:
            for obj in symbol_list:
                file.write("{} {} {}\n".format(obj.address, obj.type, obj.name))
                if obj.type == "T" or obj.type == "t":
                    if name_occurrences[obj.name] > 1:
                        send_line_to_addr2line(addr2line_process, obj.address)
                        output = fetch_line_from_addr2line(addr2line_process)
                        output = fetch_line_from_addr2line(addr2line_process)
                        decoration = "@" + "".join(["_" if not c.isalnum() else c for c in output.replace(config.linux_base_dir, "")])
                        file.write("{} {} {}\n".format(obj.address, obj.type, obj.name + decoration))

        addr2line_process.stdin.close()
        addr2line_process.stdout.close()
        addr2line_process.stderr.close()
        addr2line_process.wait()

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        raise SystemExit("Script terminated due to an error")
