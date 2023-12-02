#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2023 Red Hat, Inc. Alessandro Carminati <alessandro.carminati@gmail.com>
#
# kas_alias: Adds alias to duplicate symbols for the kallsyms output.

import os
import re
import sys
import signal
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

class Addr2LineError(Exception):
    pass

debug = DebugLevel.PRODUCTION

modules_journal = {}
journal_fn = "modules.journal"
Line = namedtuple('Line', ['address', 'type', 'name', 'addr_int'])

def handle_signal(signum, frame):
    save_journal_and_exit(-2, "signal", "termination/ctrl-c")

def save_journal_and_exit(exit_cause, exception_type, error_message):
    if exit_cause != 0:
        if journal_fn != "None":
            with open(journal_fn, 'w') as file:
                for key, value in modules_journal.items():
                    file.write(f"{key}:{value}\n")

        if exit_cause <= -2:
            print(f"Script terminated due to an error ({exception_type}): {error_message}")

    sys.exit(exit_cause)

def get_caller():
    """
    Used only to produce debug messages:
    Gets the caller's caller name if any, "kas_alias" otherwise
    Args:
      None
    Returns:
      A string representing a name of a function.
    """
    stack = inspect.stack()
    if len(stack) > 2:
        caller = stack[2][0]
        caller_name = caller.f_code.co_name
        return caller_name
    else:
        return "kas_alias"

def debug_print(print_debug_level, text):
    """
    Prints text if current debug level is greater or equal to print_debug_level.
    Args:
      current_debug_level: Application debug level specified by command line.
      print_debug_level: Minimum debug level message should be printed.
      text: string representing the message.
    Returns:
      Nothing.
    """
    if debug >= print_debug_level:
        print(f"{get_caller()}: " + text)

def parse_nm_lines(lines, name_occurrences=None):
    """
    Parses a given nm output and returns the symbol list along with a hash of
    symbol occurrences.
    Args:
      lines: List of tuples representing one nm line.
      name_occurrences: Hash having the name as key, used to count names'
                        occurrences.
    Returns:
      Creates a new line list proper for the nm output it parsed and, updates
      the occurrences hash.
    """
    debug_print(DebugLevel.DEBUG_BASIC.value, "parse_nm_lines: parse start")

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

def start_addr2line_process(binary_file, addr2line_file):
    """
    Initializes an addr2line server process operating on the given ELF object.
    Args:
      binary_file: String representing the binary file name object of addr2line
                   queries.
      addr2line_file: String representing the addr2line executable name.
    Returns:
      Returns addr2line process descriptor.
    """
    debug_print(DebugLevel.DEBUG_BASIC.value, f"Starting addr2line process on {binary_file}")

    try:
        addr2line_process = subprocess.Popen([addr2line_file, '-fe',
                                             binary_file],
                                             stdin=subprocess.PIPE,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE,
                                             text=True)
        return addr2line_process
    except Exception as e:
        save_journal_and_exit(-2, type(e).__name__, str(e))

def addr2line_fetch_address(addr2line_process, address):
    """
    Queries a specific address using the active addr2line process.
    Args:
      addr2line_process: Descriptor of the addr2line process that is wanted to
                         handle the query.
      address: The address of the symbol that needs to be resolved.
    Returns:
      Returns a string representing the file and line number where the symbol
      at the specified address has been defined. The address is normalized
      before being returned.
  """
    debug_print(DebugLevel.DEBUG_ALL.value, f"Resolving {address}")

    try:
        addr2line_process.stdin.write(address + '\n')
        addr2line_process.stdin.flush()
        addr2line_process.stdout.readline().strip()
        output = addr2line_process.stdout.readline().strip()

        return os.path.normpath(output)
    except Exception as e:
        save_journal_and_exit(-2, type(e).__name__, str(e))

def process_line(line, process_data_sym, section_map):
    """
    Determines whether a duplicate item requires an alias or not.
    Args:
      line: nm line object that needs to be checked.
      section_map: map correlating symbols and the ELF section they are from
    Returns:
      Returns true if the line needs to be processed, false otherwise.
    """
    debug_print(DebugLevel.DEBUG_ALL.value, f"Processing {line.address} {line.type} {line.name}")

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

    if process_data_sym:
        return not (any(re.match(regex, line.name) for regex in regex_filter))
    else:
        return (line.type in {"T", "t"}) and (
                not (any(re.match(regex, line.name) for regex in regex_filter)))

def fetch_file_lines(filename):
    """
    Reads a text file and retrieves its content.
    Args:
      filename: String representing the name of the file that needs to be read.
    Returns:
      Returns a string list representing the lines read in the file.
    """
    debug_print(DebugLevel.DEBUG_BASIC.value, f"Fetch {filename}")

    try:
        with open(filename, 'r') as file:
            lines = [line.strip() for line in file.readlines()]
        return lines
    except FileNotFoundError:
        save_journal_and_exit(-2, type(FileNotFoundError).__name__, str(FileNotFoundError))

def do_nm(filename, nm_executable):
    """
    Runs the nm command on a specified file.
    Args:
      filename: String representing the name of the file on which nm should
      run against.
      nm_executable: String representing the nm executable filename.
    Returns:
      Returns a strings list representing the nm output.
    """
    debug_print(DebugLevel.DEBUG_BASIC.value, f"executing {nm_executable} -n {filename}")

    try:
        nm_output = subprocess.check_output([nm_executable, '-n', filename],
                      universal_newlines=True, stderr=subprocess.STDOUT).splitlines()
        return nm_output
    except subprocess.CalledProcessError as e:
        save_journal_and_exit(-2, type(e).__name__, str(e))

def make_objcpy_arg(line, decoration, section_map):
    """
    Produces an objcopy argument statement for a single alias to be added in a
    module.
    Args:
      line: nm line object target for this iteration.
      decoration: String representing the decoration (normalized addr2line
                  output) to be added at the symbol name to have the alias.
      section_map: map correlating symbols and the ELF section they are from
    Returns:
      Returns a string that directly maps the argument string objcopy should
      use to add the alias.
    """
    try:
        flag = "global" if line.type.isupper() else "local"
        debug_print(DebugLevel.DEBUG_MODULES.value,
                 f"{line.name + decoration}={section_map[line.name]}:0x{line.address},{flag}")
        return (
                "--add-symbol "
                f"{line.name + decoration}={section_map[line.name]}:0x{line.address},{flag} "
               )
    except Exception:
        print(
              f"make_objcpy_arg warning: Skip alias for {line.name}"
              f" type {line.type} because no corresponding section found.")
        return ""

def execute_objcopy(objcopy_executable, objcopy_args, object_file):
    """
    Uses objcopy to add aliases to a given module object file.
    Since objcopy can't operate in place, the original object file is renamed
    before operating on it. At function end, a new object file having the old
    object's name is carrying the aliases for the duplicate symbols.
    Args:
      objcopy_executable: String representing the object copy executable file.
      objcopy_args: Arguments (aliases to add to the object file) to be used
                    in the objcopy execution command line.
      object_file: Target object file (module object file) against which objcopy is executed.
    Returns:
      Nothing is returned, but as a side effect of this function execution,
      the module's object file contains the aliases for duplicated symbols.
    """
    # Rename the original object file by adding a suffix
    backup_file = object_file + '.orig'
    debug_print(DebugLevel.DEBUG_MODULES.value, f"rename {object_file} to {backup_file}")
    os.rename(object_file, backup_file)

    full_command = (
                    f"{objcopy_executable} "
                    f"{objcopy_args} {backup_file} {object_file}"
                   )
    debug_print(DebugLevel.DEBUG_MODULES.value, f"executing {full_command}")

    try:
        subprocess.run(full_command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        save_journal_and_exit(-2, type(e).__name__, str(e))
#        os.rename(backup_file, object_file)
#        raise SystemExit(f"Fatal: Error executing objcopy: {e}")

def generate_decoration(line, config, addr2line_process):
    """
    Generates symbol decoration to be used to make the alias name, by
    querying addr2line.
    Args:
      line: nm line object that needs an alias.
      config: Object containing command line configuration.
      addr2line_process: Descriptor of the addr2line process that serves
                         the binary object where the symbol belongs.
    Returns:
      Returns a string representing the decoration for the given symbol,
      or empty string if this can not be done. E.g., addr2line can't find
      the point where the symbol is defined.
    """
    output = addr2line_fetch_address(addr2line_process, line.address)
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
    """
    checks if a section is of interest.
    Args:
      section: string representing the section needed to be tested.
    Returns:
      True if it is, False otherwise.
    """
    sections_regex = [r".text", r".data", r".bss", r".rodata"]

    for pattern in sections_regex:
        if re.search(pattern, section):
            return True
    return False

def get_symbol2section(objdump_executable, file_to_operate):
    """
    This function aims to produce a map{symbol_name]=section_name for
    any given object file.
    Args:
      objdump_executable: String representing the objdump executable.
      file_to_operate: file whose section names are wanted.
    Returns:
      Returns a map, where the key is the symbol name and the value is
      a section name.
    """
    try:
        output = subprocess.check_output(
                   [objdump_executable, '-h', file_to_operate],
                   universal_newlines=True)
        section_pattern = re.compile(r'^ *[0-9]+ ([.a-z_]+) +([0-9a-f]+).*$', re.MULTILINE)
        section_names = section_pattern.findall(output)
        result = {}
        for section, section_siza in section_names:
            if int(section_siza, 16) != 0 and section_interesting(section):
                debug_print(DebugLevel.DEBUG_ALL.value, f"CMD => {objdump_executable} -tj {section} {file_to_operate}")
                try:
                    output = subprocess.check_output(
                           [objdump_executable, '-tj', section, file_to_operate],
                           universal_newlines=True)
                except subprocess.CalledProcessError:
                      pass
                func_names_pattern = re.compile(r'[0-9a-f]+.* ([.a-zA-Z_][.A-Za-z_0-9]+)$', re.MULTILINE)
                matches = func_names_pattern.findall(output)
                for func_name in matches:
                    result[func_name] = section


    except Exception as e:
        save_journal_and_exit(-2, type(e).__name__, str(e))
    return result

def produce_output_modules(config, symbol_list, name_occurrences,
                           module_file_name, addr2line_process):
    """
    Computes the alias addition on a given module object file.
    Args:
      config: Object containing command line configuration.
      symbol_list: List of tuples representing nm lines for the given object
                   file.
      name_occurrences: Hash that stores symbol occurrences for the build.
      module_file_name: String representing the target moule object file.
      addr2line_process: Descriptor of the addr2line process that is wanted to
                         handle the query.
    Returns:
      Nothing is returned, but as a side effect of this function execution,
      the module's object file contains the aliases for duplicated symbols.
    """
    debug_print(DebugLevel.DEBUG_ALL.value, "produce_output_modules computation starts here ")
    objcopy_args = "";
    args_cnt = 0
    section_map = get_symbol2section(config.objdump_file, module_file_name)
    for module_symbol in symbol_list:
        debug_print(DebugLevel.DEBUG_ALL.value, f"--> Processing {module_symbol}")
        if (name_occurrences[module_symbol.name] > 1) and process_line(module_symbol, config.process_data_sym, section_map):
            decoration = generate_decoration(module_symbol, config, addr2line_process)
            debug_print(DebugLevel.DEBUG_ALL.value, f"--- {module_symbol} occurred multiple times and is a candidate for alias: decoration '{decoration}'")
            if decoration != "":
                objcopy_args = objcopy_args + make_objcpy_arg(module_symbol, decoration, section_map)
                args_cnt = args_cnt + 1
                if args_cnt > 50:
                   debug_print(DebugLevel.DEBUG_MODULES.value, "Number of arguments high, split objcopy"
                               " call into multiple statements.")
                   execute_objcopy(config.objcopy_file, objcopy_args, module_file_name)
                   args_cnt = 0
                   objcopy_args = ""

    execute_objcopy(config.objcopy_file, objcopy_args, module_file_name)

def produce_output_vmlinux(config, symbol_list, name_occurrences, addr2line_process):
    """
    Computes the alias addition for the core Linux on image.
    Args:
      config: Object containing command line configuration.
      symbol_list: List of tuples representing nm lines for the given object
                   file.
      name_occurrences: Hash that stores symbol occurreces for the build.
      addr2line_process: Descriptor of the addr2line process that is wanted to
                         handle the query.
    Returns:
      Nothing is returned, but as a side effect of this function execution,
      the core kernel image contains the aliases for duplicated symbols.
    """
    with open(config.output_file, 'w') as output_file:
       for obj in symbol_list:
            output_file.write(f"{obj.address} {obj.type} {obj.name}\n")
            if (name_occurrences[obj.name] > 1) and process_line(obj, config.process_data_sym, None):
                decoration = generate_decoration(obj, config, addr2line_process)
                debug_print(DebugLevel.DEBUG_ALL.value, f"Symbol {obj.name} appears multiple times, and decoration is {decoration}")
                if decoration != "":
                    debug_print(DebugLevel.DEBUG_ALL.value, f"Writing on {config.output_file} the additional '{obj.address} {obj.type} {obj.name + decoration}'")
                    output_file.write(f"{obj.address} {obj.type} {obj.name + decoration}\n")

if __name__ == "__main__":
    #register signal handlers
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Handles command-line arguments and generates a config object
    parser = argparse.ArgumentParser(description='Add alias to multiple occurring symbols name in kallsyms')
    subparsers = parser.add_subparsers(title='Subcommands', dest='action')
    core_image_parser = subparsers.add_parser('core_image', help='Operates for in tree computation.')
    core_image_parser.add_argument('-n', "--nmdata", dest="nm_data_file", required=True, help="Set vmlinux nm output file to use for core image.")
    core_image_parser.add_argument('-o', "--outfile", dest="output_file", required=True, help="Set the vmlinux nm output file containing aliases.")
    core_image_parser.add_argument('-v', "--vmlinux", dest="vmlinux_file", required=True, help="Set the vmlinux core image file.")

    modules_parser = subparsers.add_parser('modules', help='Operates for out of tree computation.')
    modules_parser.add_argument('-c', "--objcopy", dest="objcopy_file", required=True, help="Set the objcopy executable to be used.")
    modules_parser.add_argument('-u', "--objdump", dest="objdump_file", required=True, help="Set objdump  executable to be used.")

    parser.add_argument('-j', "--symbol_frequency", dest="symbol_frequency_file", required=True, help="Specify the symbol frequency needed to use for producing aliases")
    parser.add_argument('-k', "--symbol_module", dest="module_symbol_list_file", required=True, help="Specify the module symbols data file needed to use for producing aliases")
    parser.add_argument('-z', "--debug", dest="debug", required=False, help="Set the debug level.", choices=[f"{level.value}" for level in DebugLevel], default="1" )
    parser.add_argument('-a', "--addr2line", dest="addr2line_file", required=True, help="Set the addr2line executable to be used.")
    parser.add_argument('-b', "--basedir", dest="linux_base_dir", required=True, help="Set base directory of the source kernel code.")
    parser.add_argument('-s', "--separator", dest="separator", required=False, help="Set separator, character that separates original name from the addr2line data in alias symbols.", default="@", type=SeparatorType())
    parser.add_argument('-d', "--process_data", dest="process_data_sym", required=False, help="Requires the tool to process data symbols along with text symbols.", action='store_true')
    parser.add_argument('-m', "--modules_list", dest="module_list", required=True, help="Set the file containing the list of the modules object files.")
    parser.add_argument('-e', "--nm", dest="nm_file", required=True, help="Set the nm executable to be used.")

    config = parser.parse_args()
    debug = int(config.debug)

    try:
        # The core_image target is utilized for gathering symbol statistics from the core image and modules,
        # generating aliases for the core image. This target is designed to be invoked from scripts/link-vmlinux.sh
        if config.action == 'core_image':
            debug_print(DebugLevel.INFO.value,"Start core_image processing")

            # Determine kernel source code base directory
            if not config.linux_base_dir.startswith('/'):
                config.linux_base_dir = os.path.normpath(os.getcwd() + "/" + config.linux_base_dir) + "/"
            debug_print(DebugLevel.DEBUG_BASIC.value, f"Configuration: {config}")

            debug_print(DebugLevel.INFO.value, "Process nm data from vmlinux")
            # Process nm data from vmlinux
            debug_print(DebugLevel.DEBUG_BASIC.value, f"fetch_file_lines({config.nm_data_file})")
            vmlinux_nm_lines = fetch_file_lines(config.nm_data_file)
            vmlinux_symbol_list, name_occurrences = parse_nm_lines(vmlinux_nm_lines)

            debug_print(DebugLevel.INFO.value,"Process nm data for modules")
            # Process nm data for modules
            debug_print(DebugLevel.DEBUG_BASIC.value, f"fetch_file_lines({config.nm_data_file})")
            module_list = fetch_file_lines(config.module_list)
            module_symbol_list = {}
            for module in module_list:
                modules_journal[module] = 0
                module_nm_lines = do_nm(module, config.nm_file)
                module_symbol_list[module], name_occurrences = parse_nm_lines(module_nm_lines, name_occurrences)

            debug_print(DebugLevel.INFO.value, f"Save name_occurrences data: {config.symbol_frequency_file}")
            with open(config.symbol_frequency_file, 'w') as file:
                for key, value in name_occurrences.items():
                    file.write(f"{key}:{value}\n")

            debug_print(DebugLevel.INFO.value, "Save {journal_fn} data")
            with open(journal_fn, 'w') as file:
                for key, value in modules_journal.items():
                    file.write(f"{key}:{value}\n")

            debug_print(DebugLevel.INFO.value, f"Save module_symbol_list data: {config.module_symbol_list_file}")
            with open(config.module_symbol_list_file, 'w') as file:
                for key, value in module_symbol_list.items():
                    file.write(f"{key}:\n")
                    for line in value:
                        file.write(f"{line.address},{line.type},{line.name},{line.addr_int}\n")
                    file.write("---\n")

            debug_print(DebugLevel.INFO.value, "Produce file for vmlinux")
            # Produce file for vmlinux
            debug_print(DebugLevel.DEBUG_BASIC.value, f"addr2line_process({config.vmlinux_file}, {config.addr2line_file})")
            addr2line_process = start_addr2line_process(config.vmlinux_file, config.addr2line_file)
            produce_output_vmlinux(config, vmlinux_symbol_list, name_occurrences, addr2line_process)
            addr2line_process.stdin.close()
            addr2line_process.stdout.close()
            addr2line_process.stderr.close()
            addr2line_process.wait()

        # Expects to be called from scripts/Makefile.modfinal
        elif config.action == 'modules':
            debug_print(DebugLevel.INFO.value,"Start modules processing")
            try:
                with open(journal_fn, 'r') as file:
                    for line in file:
                        key, value = line.strip().split(':')
                        modules_journal[key]=int(value)
            except FileNotFoundError:
                pass


            name_occurrences = {}
            # This code expects to open and read config.symbol_frequency_file, which defaults
            # to modules.symbfreq, to fetch module symbol statistics.
            # In a complete build, this file is generated in an earlier step of the build phase,
            # so the expectation is fulfilled.
            # However, when building a custom OOT, it is necessary to ensure that this file is
            # accessible in the current directory where the module source code is being built.
            try:
                with open(config.symbol_frequency_file, 'r') as file:
                    for line in file:
                        key, value = line.strip().split(':')
                        name_occurrences[key]=int(value)
            except FileNotFoundError:
                pass

            module_symbol_list = {}
            # This segment assumes the existence of config.module_symbol_list_file, which defaults
            # to modules.symbmod, containing module data resulting from previous computations when
            # core image symbol aliases were added.
            # In the case of a custom OOT module, the file is not expected to exist;
            # if it does, it will be loaded, although its contents are unlikely to be utilized.
            try:
                with open(config.module_symbol_list_file, 'r') as file:
                    current_key = None
                    current_list = []
                    for line in file:
                        line = line.strip()
                        if line.startswith("---"):
                            module_symbol_list[current_key] = current_list
                            current_key = None
                            current_list = []
                        elif line.endswith(":"):
                            current_key = line[:-1]
                        else:
                            data = line.split(',')
                            data[-1] = int(data[-1])
                            current_list.append(Line(*data))
            except FileNotFoundError:
                pass

            debug_print(DebugLevel.INFO.value, "Add aliases to module files")
            module_list = fetch_file_lines(config.module_list)
            # Add aliases to module files
            for module in module_list:
                if modules_journal[module] == 1:
                    debug_print(DebugLevel.DEBUG_ALL.value, f"{module} is half done: check if restore's needed")
                    backup_file = module + '.orig'
                    if os.path.exists(backup_file):
                        debug_print(DebugLevel.INFO.value, f"restore: {module} is not clean, restore {backup_file}")
                        os.rename(backup_file, module)
                elif modules_journal[module] == 2:
                    debug_print(DebugLevel.DEBUG_ALL.value, f"skipping {module}: already done")
                    continue

                modules_journal[module] = 1
                debug_print(DebugLevel.DEBUG_BASIC.value, f"addr2line_process({module}, {config.addr2line_file})")
                addr2line_process = start_addr2line_process(module, config.addr2line_file)
                # Custom modules compiled OOT are not part of module_symbol_list, so before proceeding, they need to be added
                if module not in module_symbol_list:
                   debug_print(DebugLevel.DEBUG_BASIC.value, f"module '{module}' not in list, possibly custom OOT, fetching symbol data.")
                   module_nm_lines = do_nm(module, config.nm_file)
                   module_symbol_list[module], name_occurrences = parse_nm_lines(module_nm_lines, name_occurrences)

                debug_print(DebugLevel.DEBUG_ALL.value, f"executing produce_output_modules on {module}")
                produce_output_modules(config, module_symbol_list[module], name_occurrences, module, addr2line_process)
                addr2line_process.stdin.close()
                addr2line_process.stdout.close()
                addr2line_process.stderr.close()
                addr2line_process.wait()
                modules_journal[module] = 2

        else:
            raise SystemExit("Script terminated: unknown action")

    except Exception as e:
        exit_cause = -2
        exception_type = type(e).__name__
        error_message = str(e)
        save_journal_and_exit(-2, type(e).__name__, str(e))
