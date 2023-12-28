#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2023 Red Hat, Inc. Alessandro Carminati <alessandro.carminati@gmail.com>
#
# kas_alias: Adds alias to duplicate symbols for the kallsyms output.

import os
import re
import sys
import inspect
import argparse
import subprocess
from enum import Enum
from collections import namedtuple

# Regex representing symbols that need no alias
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
        "^__cfi_.*$",
        "^\\.LC[0-9]+$",
        "^\\.L[0-9]+.[0-9]+$",
        "^__UNIQUE_ID_.*$",
        "^symbols\\.[0-9]+$",
        "^_note_[0-9]+$"
        ]

class DebugLevel(Enum):
    PRODUCTION = 0
    INFO = 1
    DEBUG_BASIC = 2
    DEBUG_MODULES = 3
    DEBUG_ALL = 4

class SeparatorType:
    def __call__(self, separator):
        if len(separator) != 1:
            raise argparse.ArgumentTypeError("Separator must be a single character")
        return separator

Line = namedtuple('Line', ['address', 'type', 'name', 'addr_int'])

def get_caller():
    """Used only to produce debug messages: returns the caller's caller name if any, 
    "kas_alias" otherwise

    :return: A string representing a name of a function.
    :rtype: str
    """
    stack = inspect.stack()
    if len(stack) > 2:
        caller = stack[2][0]
        caller_name = caller.f_code.co_name
        return caller_name
    else:
        return "kas_alias"

def debug_print(config, print_debug_level, text):
    """Prints text if current debug level is greater or equal to print_debug_level.

    :param config: object containing the current config parsed from command line
    :type config: object
    :param print_debug_level: Minimum debug level message should be printed.
    :type print_debug_level: int
    :param text: string representing the message.
    :type text: str
    """
    if int(config.debug) >= print_debug_level:
        print(f"{get_caller()}: " + text)

def parse_nm_lines(config, lines, name_occurrences=None):
    """Parses a given nm output and returns the symbol list along with a hash of
    symbol occurrences.

    :param config: object containing the current config parsed from command line
    :type config: object
    :param lines: List of tuples representing one nm line.
    :type lines: List of Line
    :param name_occurrences: Hash having the name as key, used to count names' occurrences.
    :type name_occurrences: map[string]=int

    :return: two elements tuple containing: a new line list proper for the nm output it parsed 
       and, updates the occurrences hash.
    :rtype: tuple
    """
    debug_print(config, DebugLevel.DEBUG_BASIC.value, "parse_nm_lines: parse start")

    if name_occurrences is None:
        name_occurrences = {}

    symbol_list = []

    for line in lines:
        fields = line.strip().split()

        if len(fields) >= 3:
            address, type, name = fields[0], fields[1], ' '.join(fields[2:])
            symbol_list.append(Line(address, type, name, int(address, 16)))
            name_occurrences[name] = name_occurrences.get(name, 0) + 1

    return symbol_list, name_occurrences

def start_addr2line_process(binary_file, config):
    """Initializes an addr2line server process operating on the given ELF object.

    :param binary_file: String representing the binary file name object of addr2line queries.
    :type binary_file: str
    :param config: object containing the current config parsed from command line
    :type config: object
    :return: addr2line process descriptor.
    :rtype: process descriptor
    """
    debug_print(config, DebugLevel.DEBUG_BASIC.value, f"Starting addr2line process on {binary_file}")

    try:
        addr2line_process = subprocess.Popen([config.addr2line_file, '-fe',
                                             binary_file],
                                             stdin=subprocess.PIPE,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE,
                                             text=True)
        return addr2line_process
    except Exception as e:
        debug_print(config, DebugLevel.PRODUCTION.value, f"Script terminated due to an error ({type(e).__name__}): {str(e)}")
        sys.exit(-2)

def addr2line_fetch_address(config, addr2line_process, address):
    """Queries a specific address using the active addr2line process.

    :param config: object containing the current config parsed from command line
    :type config: object
    :param addr2line_process: Descriptor of the addr2line process that is wanted to handle the query.
    :type addr2line_process: process descriptor
    :param address: The address of the symbol that needs to be resolved.
    :type address: str
    :return: a string representing the file and line number where the symbol at the specified address
         has been defined. The address is normalized before being returned.
    :rtype: str
  """
    debug_print(config, DebugLevel.DEBUG_ALL.value, f"Resolving {address}")

    try:
        addr2line_process.stdin.write(address + '\n')
        addr2line_process.stdin.flush()
        addr2line_process.stdout.readline().strip()
        output = addr2line_process.stdout.readline().strip()

        return os.path.normpath(output)
    except Exception as e:
        debug_print(config, DebugLevel.PRODUCTION.value, f"Script terminated due to an error ({type(e).__name__}): {str(e)}")
        sys.exit(-2)

def process_line(line, config, section_map):
    """Determines whether a duplicate item requires an alias or not.

    :param line: nm line object that needs to be checked.
    :type line: list of Line
    :param section_map: map correlating symbols and the ELF section they are from
    :type section_map: map[str]=str
    :param config: object containing the current config parsed from command line
    :type config: object
    :return: true if the line needs to be processed, false otherwise.
    :rtype: bool
    """
    debug_print(config, DebugLevel.DEBUG_ALL.value, f"Processing {line.address} {line.type} {line.name}")

    # The module contains symbols that were discarded after being loaded. Typically,
    # these symbols belong to the initialization function. These symbols have their
    # address in the init section addresses, so this check prevents these symbols
    # from being assigned aliases.
    if section_map != None:
       if line.name in section_map:
          if (".init" in section_map[line.name] or ".exit" in section_map[line.name]):
              return False
       else:
          return False

    if config.process_data_sym:
        return not (any(re.match(regex, line.name) for regex in regex_filter))
    else:
        return (line.type in {"T", "t"}) and (
                not (any(re.match(regex, line.name) for regex in regex_filter)))

def fetch_file_lines(config, filename):
    """Reads a text file and retrieves its content.

    :param filename: String representing the name of the file that needs to be read.
    :type filename: str
    :param config: object containing the current config parsed from command line
    :type config: object
    :return: a string list representing the lines read in the file.
    :rtype: list of str
    """
    debug_print(config, DebugLevel.DEBUG_BASIC.value, f"Fetch {filename}")

    try:
        with open(filename, 'r') as file:
            lines = [line.strip() for line in file.readlines()]
        return lines
    except FileNotFoundError:
        debug_print(config, DebugLevel.PRODUCTION.value, f"Script terminated due to an error ({type(FileNotFoundError).__name__}): {str(FileNotFoundError)}")
        sys.exit(-2)

def do_nm(filename, config):
    """Runs the nm command on a specified file.

    :param filename: String representing the name of the file on which nm should run against.
    :type filename: str
    :param config: object containing the current config parsed from command line
    :type config: object
    :return: a strings list representing the nm output.
    :rtype: list of str
    """
    debug_print(config, DebugLevel.DEBUG_BASIC.value, f"executing {config.nm_file} -n {filename}")

    try:
        nm_output = subprocess.check_output([config.nm_file, '-n', filename],
                      universal_newlines=True, stderr=subprocess.STDOUT).splitlines()
        return nm_output
    except subprocess.CalledProcessError as e:
        debug_print(config, DebugLevel.PRODUCTION.value, f"Script terminated due to an error ({type(e).__name__}): {str(e)}")
        sys.exit(-2)

def make_objcpy_arg(config, line, decoration, section_map):
    """Produces an objcopy argument statement for a single alias to be added in a module.

    :param line: nm line object target for this iteration.
    :type line: list of Line
    :param decoration: String representing the decoration (normalized addr2line output) to be added at the symbol name to have the alias.
    :type decoration: str
    :param section_map: map correlating symbols and the ELF section they are from
    :type section_map: map[str]=str
    :param config: object containing the current config parsed from command line
    :type config: object
    :return: a string that directly maps the argument string objcopy should use to add the alias.
    :rtype: str
    """
    try:
        flag = "global" if line.type.isupper() else "local"
        debug_print(config, DebugLevel.DEBUG_MODULES.value,
                 f"{line.name + decoration}={section_map[line.name]}:0x{line.address},{flag}")
        return (
                "--add-symbol "
                f"{line.name + decoration}={section_map[line.name]}:0x{line.address},{flag} "
               )
    except Exception:
        debug_print(config, DebugLevel.PRODUCTION.value,
              f"make_objcpy_arg warning: Skip alias for {line.name}"
              f" type {line.type} because no corresponding section found.")
        return ""

def execute_objcopy(config, objcopy_args, object_file):
    """Uses objcopy to add aliases to a given module object file. Since objcopy can't operate in place,
    the original object file is renamed before operating on it. At function end, a new object file
    having the old object's name is carrying the aliases for the duplicate symbols.

    :param config: object containing the current config parsed from command line
    :type config: object
    :param objcopy_args: Arguments (aliases to add to the object file) to be used in the objcopy execution command line.
    :type objcopy_args: str
    :param object_file: Target object file (module object file) against which objcopy is executed.
    :type object_file: str
    :return: Nothing is returned, but as a side effect of this function execution, the module's object file contains 
       the aliases for duplicated symbols.
    :rtype: None
    """
    # Rename the original object file by adding a suffix
    backup_file = object_file + '.orig'
    debug_print(config, DebugLevel.DEBUG_MODULES.value, f"rename {object_file} to {backup_file}")
    os.rename(object_file, backup_file)

    full_command = (
                    f"{config.objcopy_file} "
                    f"{objcopy_args} {backup_file} {object_file}"
                   )
    debug_print(config, DebugLevel.DEBUG_MODULES.value, f"executing {full_command}")

    try:
        subprocess.run(full_command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        debug_print(config, DebugLevel.PRODUCTION.value, f"Script terminated due to an error ({type(e).__name__}): {str(e)}")
        sys.exit(-2)

def generate_decoration(line, config, addr2line_process):
    """Generates symbol decoration to be used to make the alias name, by querying addr2line.

    :param line: nm line object that needs an alias.
    :type line: 
    :param config: object containing the current config parsed from command line
    :type config: object
    :param addr2line_process: Descriptor of the addr2line process that serves the binary object where the symbol belongs.
    :type addr2line_process: 
    :return: Returns a string representing the decoration for the given symbol, or empty string if this can not be done. 
       E.g., addr2line can't find the point where the symbol is defined.
    :rtype: str
    """
    output = addr2line_fetch_address(config, addr2line_process, line.address)
    base_dir = config.linux_base_dir + "/"
    cwd = os.getcwd() + "/"
    absolute_base_dir = os.path.abspath(os.path.join(cwd, base_dir))

    if output.startswith(base_dir):
        output = output[len(base_dir):]

    if output.startswith(absolute_base_dir):
        output = output[len(absolute_base_dir):]

    if output.startswith('/'):
            output = output[1:]

    decoration = config.separator + "".join(
        "_" if not c.isalnum() else c for c in output
    )
    # The addr2line can emit the special string "?:??" when addr2line can not find the
    # specified address in the DWARF section that after normalization it becomes "____".
    # In such cases, emitting an alias wouldn't make sense, so it is skipped.
    if decoration != config.separator + "____":
        return decoration
    return ""

def section_interesting(section):
    """Checks if a section is of interest.

    :param section: string representing the section needed to be tested.
    :type section: str
    :return: True if it is, False otherwise.
    :rtype: bool
    """
    sections_regex = [r".text", r".data", r".bss", r".rodata"]

    for pattern in sections_regex:
        if re.search(pattern, section):
            return True
    return False

def get_symbol2section(config, file_to_operate):
    """This function aims to produce a map[symbol_name]=section_name for any given object file.

    :param config: object containing the current config parsed from command line
    :type config: object
    :param file_to_operate: file whose section names are wanted.
    :type file_to_operate: str
    :return: Returns a map, where the key is the symbol name and the value is a section name.
    :rtype: map[str]=str
    """
    try:
        output = subprocess.check_output(
                   [config.objdump_file, '-h', file_to_operate],
                   universal_newlines=True)
        section_pattern = re.compile(r'^ *[0-9]+ ([.a-z_]+) +([0-9a-f]+).*$', re.MULTILINE)
        section_names = section_pattern.findall(output)
        result = {}
        for section, section_size in section_names:
            if int(section_size, 16) != 0 and section_interesting(section):
                debug_print(config, DebugLevel.DEBUG_ALL.value, f"CMD => {config.objdump_file} -tj {section} {file_to_operate}")
                try:
                    output = subprocess.check_output(
                           [config.objdump_file, '-tj', section, file_to_operate],
                           universal_newlines=True)
                except subprocess.CalledProcessError:
                      pass
                func_names_pattern = re.compile(r'[0-9a-f]+.* ([.a-zA-Z_][.A-Za-z_0-9]+)$', re.MULTILINE)
                matches = func_names_pattern.findall(output)
                for func_name in matches:
                    result[func_name] = section


    except Exception as e:
        debug_print(config, DebugLevel.PRODUCTION.value, f"Script terminated due to an error ({type(e).__name__}): {str(e)}")
        sys.exit(-2)
    return result

def produce_output_modules(config, symbol_list, name_occurrences, module_file_name, addr2line_process):
    """Computes the alias addition on a given module object file.

    :param config: object containing the current config parsed from command line.
    :type config: object
    :param symbol_list: List of tuples representing nm lines for the given object file.
    :type symbol_list: list of Line
    :param name_occurrences: Hash that stores symbol occurrences for the build.
    :type name_occurrences: map[str]=int
    :param module_file_name: String representing the target moule object file.
    :type module_file_name: str
    :param addr2line_process: Descriptor of the addr2line process that is wanted to handle the query.
    :type addr2line_process: process descriptor
    :return: Nothing is returned, but as a side effect of this function execution, the module's object file contains the
       aliases for duplicated symbols.
    :rtype: None
    """
    debug_print(config, DebugLevel.DEBUG_ALL.value, "produce_output_modules computation starts here ")
    objcopy_args = "";
    args_cnt = 0
    section_map = get_symbol2section(config, module_file_name)
    for module_symbol in symbol_list:
        debug_print(config, DebugLevel.DEBUG_ALL.value, f"--> Processing {module_symbol}")
        try:
            if (name_occurrences[module_symbol.name] > 1) and process_line(module_symbol, config, section_map):
                decoration = generate_decoration(module_symbol, config, addr2line_process)
                debug_print(config, DebugLevel.DEBUG_ALL.value, f"--- {module_symbol} occurred multiple times and is a candidate for alias: decoration '{decoration}'")
                if decoration != "":
                    objcopy_args = objcopy_args + make_objcpy_arg(config, module_symbol, decoration, section_map)
                    args_cnt = args_cnt + 1
                    if args_cnt > 50:
                       debug_print(config, DebugLevel.DEBUG_MODULES.value, "Number of arguments high, split objcopy"
                                   " call into multiple statements.")
                       execute_objcopy(config, objcopy_args, module_file_name)
                       args_cnt = 0
                       objcopy_args = ""
        except KeyError:
            pass
    execute_objcopy(config, objcopy_args, module_file_name)

def produce_output_vmlinux(config, symbol_list, name_occurrences, addr2line_process):
    """Computes the alias addition for the core Linux on image.

    :param config: object containing the current config parsed from command line
    :type config: object
    :param symbol_list: List of tuples representing nm lines for the given object file.
    :type symbol_list: list of Line
    :param name_occurrences: Hash that stores symbol occurreces for the build.
    :type name_occurrences: map[str]=int
    :param addr2line_process: Descriptor of the addr2line process that is wanted to handle the query.
    :type addr2line_process: process descriptor
    :return: Nothing is returned, but as a side effect of this function execution, the core kernel image 
      contains the aliases for duplicated symbols.
    :rtype: None
    """
    with open(config.output_file, 'w') as output_file:
       for obj in symbol_list:
            output_file.write(f"{obj.address} {obj.type} {obj.name}\n")
            if (name_occurrences[obj.name] > 1) and process_line(obj, config, None):
                decoration = generate_decoration(obj, config, addr2line_process)
                debug_print(config,DebugLevel.DEBUG_ALL.value, f"Symbol {obj.name} appears multiple times, and decoration is {decoration}")
                if decoration != "":
                    debug_print(config, DebugLevel.DEBUG_ALL.value, f"Writing on {config.output_file} the additional '{obj.address} {obj.type} {obj.name + decoration}'")
                    output_file.write(f"{obj.address} {obj.type} {obj.name + decoration}\n")

def read_name_occurrences(config):
    """Reads symbol frequencies from the file specified in the 'config' argument.
    If the file is not found, it gracefully returns an empty map.

    :param config: object containing the current config parsed from command line
    :type config: object
    :return: A map where keys represent symbol names and values represent their frequencies.
    :rtype: map[str]=int
    """
    name_occurrences = {}
    # This code reads occurrences of symbol names from a file containing both the core image
    # and modules frequencies resulted from the computation of the "core_image" action.
    # It reads from the file specified by command-line arguments; if the file doesn't exist
    # or the filename isn't specified, it returns an empty map.
    # The code relies on accessing and reading config.symbol_frequency_file containing
    # symbol name frequencies.
    # In a complete build, this file is generated during the "core image" action earlier
    # in the build process.
    # However, when building a custom OOT module, it is needed to ensure that this file
    # is accessible in the current directory where the module source code is being built.
    # Not having this file result in a module that have no aliases even if they are needed
    if config.symbol_frequency_file is not None:
        try:
            with open(config.symbol_frequency_file, 'r') as file:
                for line in file:
                    key, value = line.strip().split(':')
                    name_occurrences[key]=int(value)
        except FileNotFoundError:
            pass

    return name_occurrences

def check_aliases(config, module_nm_lines):
   """Flags modules that already have aliases based on the given 'module_nm_lines'.
   This function takes in configuration details and a list of strings representing
   the 'nm' command output for a specific module. It detects instances where a module
   already possesses an alias, which might occur after a build interruption and restart.
   The detection logic is straightforward: it examines if the separator character is
   present in the symbol name. If found, it uses this separator to check if the
   previous symbol shares the same name. This detection assumes 'nm' is invoked with
   the '-n' flag, ensuring symbol sorting.

   :param config: object containing the current config parsed from command line
   :type config: object
   :param module_nm_lines: A list of strings representing the 'nm' command output for a module.
   :type module_nm_lines: list of Line
   :return: True if the module_nm_lines contains aliases, False otherwise.
   :rtype: bool
   """
   prev = None
   for line in module_nm_lines:
       if (config.separator in line.name and line.name.split(config.separator)[0] == prev):
           return False
       prev = line.name
   return True

def main():
    # Handles command-line arguments and generates a config object
    parser = argparse.ArgumentParser(description='Add alias to multiple occurring symbols name in kallsyms')
    subparsers = parser.add_subparsers(title='Subcommands', dest='action')
    core_image_parser = subparsers.add_parser('core_image', help='Operates for in tree computation.')
    core_image_parser.add_argument('-n', "--nmdata", dest="nm_data_file", required=True, help="Set vmlinux nm output file to use for core image.")
    core_image_parser.add_argument('-o', "--outfile", dest="output_file", required=True, help="Set the vmlinux nm output file containing aliases.")
    core_image_parser.add_argument('-v', "--vmlinux", dest="vmlinux_file", required=True, help="Set the vmlinux core image file.")
    core_image_parser.add_argument('-m', "--modules_list", dest="module_list", required=True, help="Set the file containing the list of the modules object files.")

    single_module_parser = subparsers.add_parser('single_module', help='Operates for out of tree computation.')
    single_module_parser.add_argument('-c', "--objcopy", dest="objcopy_file", required=True, help="Set the objcopy executable to be used.")
    single_module_parser.add_argument('-u', "--objdump", dest="objdump_file", required=True, help="Set objdump  executable to be used.")
    single_module_parser.add_argument('-q', "--target-module", dest="target_module", required=False, help="Sets a tharget module to operate.")

    parser.add_argument('-j', "--symbol_frequency", dest="symbol_frequency_file", required=True, help="Specify the symbol frequency needed to use for producing aliases")
    parser.add_argument('-z', "--debug", dest="debug", required=False, help="Set the debug level.", choices=[f"{level.value}" for level in DebugLevel], default="1" )
    parser.add_argument('-a', "--addr2line", dest="addr2line_file", required=True, help="Set the addr2line executable to be used.")
    parser.add_argument('-b', "--basedir", dest="linux_base_dir", required=True, help="Set base directory of the source kernel code.")
    parser.add_argument('-s', "--separator", dest="separator", required=False, help="Set separator, character that separates original name from the addr2line data in alias symbols.", default="@", type=SeparatorType())
    parser.add_argument('-d', "--process_data", dest="process_data_sym", required=False, help="Requires the tool to process data symbols along with text symbols.", action='store_true')
    parser.add_argument('-e', "--nm", dest="nm_file", required=True, help="Set the nm executable to be used.")

    config = parser.parse_args()

    try:
        # The core_image target is utilized for gathering symbol statistics from the core image and modules,
        # generating aliases for the core image. This target is designed to be invoked from scripts/link-vmlinux.sh
        if config.action == 'core_image':
            debug_print(config, DebugLevel.INFO.value,"Start core_image processing")

            # Determine kernel source code base directory
            if not config.linux_base_dir.startswith('/'):
                config.linux_base_dir = os.path.normpath(os.getcwd() + "/" + config.linux_base_dir) + "/"
            debug_print(config, DebugLevel.DEBUG_BASIC.value, f"Configuration: {config}")

            debug_print(config, DebugLevel.INFO.value, "Process nm data from vmlinux")
            # Process nm data from vmlinux
            debug_print(config, DebugLevel.DEBUG_BASIC.value, f"fetch_file_lines({config.nm_data_file})")
            vmlinux_nm_lines = fetch_file_lines(config, config.nm_data_file)
            vmlinux_symbol_list, name_occurrences = parse_nm_lines(config, vmlinux_nm_lines)

            debug_print(config, DebugLevel.INFO.value,"Process nm data for modules")
            # Process nm data for modules
            debug_print(config, DebugLevel.DEBUG_BASIC.value, f"fetch_file_lines({config.nm_data_file})")
            module_list = fetch_file_lines(config, config.module_list)
            module_symbol_list = {}
            for module in module_list:
                module_nm_lines = do_nm(module, config)
                module_symbol_list[module], name_occurrences = parse_nm_lines(config, module_nm_lines, name_occurrences)

            debug_print(config, DebugLevel.INFO.value, f"Save name_occurrences data: {config.symbol_frequency_file}")
            with open(config.symbol_frequency_file, 'w') as file:
                for key, value in name_occurrences.items():
                    file.write(f"{key}:{value}\n")

            debug_print(config, DebugLevel.INFO.value, "Produce file for vmlinux")
            # Produce file for vmlinux
            debug_print(config, DebugLevel.DEBUG_BASIC.value, f"addr2line_process({config.vmlinux_file}, {config.addr2line_file})")
            addr2line_process = start_addr2line_process(config.vmlinux_file, config)
            produce_output_vmlinux(config, vmlinux_symbol_list, name_occurrences, addr2line_process)
            addr2line_process.stdin.close()
            addr2line_process.stdout.close()
            addr2line_process.stderr.close()
            addr2line_process.wait()

        # Expects to be called from scripts/Makefile.modfinal
        elif config.action == 'single_module':
             debug_print(config, DebugLevel.INFO.value,"Start single_module processing")
             # read symbol name frequency file
             name_occurrences = read_name_occurrences(config)
             # scan current module
             module_nm_lines = do_nm(config.target_module, config)
             mudule_nm_data, _ = parse_nm_lines(config, module_nm_lines)
             if check_aliases(config, mudule_nm_data,):
                 debug_print(config, DebugLevel.DEBUG_BASIC.value, f"addr2line_process({config.target_module}, {config.addr2line_file})")
                 addr2line_process = start_addr2line_process(config.target_module, config)
                 debug_print(config, DebugLevel.DEBUG_BASIC.value,"adding aliases to module")
                 produce_output_modules(config, mudule_nm_data, name_occurrences, config.target_module, addr2line_process)
                 addr2line_process.stdin.close()
                 addr2line_process.stdout.close()
                 addr2line_process.stderr.close()
                 addr2line_process.wait()
             else:
                 debug_print(config, DebugLevel.INFO.value,"module is already aliased, skipping")

        else:
            raise SystemExit("Script terminated: unknown action")

    except Exception as e:
        debug_print(config, DebugLevel.PRODUCTION.value, f"Script terminated due to an error ({type(e).__name__}): {str(e)}")
        sys.exit(-2)

if __name__ == "__main__":
    main()
