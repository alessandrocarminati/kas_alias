import subprocess
import sys
import os

class Line:
    def __init__(self, address, type, name):
        self.address = address
        self.type = type
        self.name = name

def parse_file(filename):
    symbol_list = []
    name_occurrences = {}

    with open(filename, 'r') as file:
        for line in file:
            fields = line.strip().split()

            if len(fields) >= 3:
                address = fields[0]
                type = fields[1]
                name = ' '.join(fields[2:])

                line = Line(address, type, name)
                symbol_list.append(line)
                name_occurrences[name] = name_occurrences.get(name, 0) + 1

    return symbol_list, name_occurrences

def find_duplicate(symbol_list, name_occurrences):
    name_to_lines = {}
    duplicate_lines = []

    for line in symbol_list:
        if line.name in name_to_lines:
            first_occurrence = name_to_lines[line.name]
            duplicate_lines.append(first_occurrence)
            duplicate_lines.append(line)
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

class Configuration:
    def __init__(self):
        self.addr2line_file = None
        self.vmlinux_file = None
        self.output_file = None
        self.nm_data_file = None
        self.linux_base_dir = None

def parse_command_line(args):
    config = Configuration()
    i = 1

    required_options = ['addr2line_file', 'vmlinux_file', 'output_file', 'nm_data_file']

    while i < len(args):
        if args[i] == '-a' and i + 1 < len(args):
            config.addr2line_file = args[i + 1]
            i += 1
        elif args[i] == '-v' and i + 1 < len(args):
            config.vmlinux_file = args[i + 1]
            i += 1
        elif args[i] == '-o' and i + 1 < len(args):
            config.output_file = args[i + 1]
            i += 1
        elif args[i] == '-n' and i + 1 < len(args):
            config.nm_data_file = args[i + 1]
            i += 1
        else:
            return None

        i += 1

    for option in required_options:
        if getattr(config, option) is None:
            return None

    if config.vmlinux_file:
        config.linux_base_dir = os.path.dirname(config.vmlinux_file)

    return config

if __name__ == "__main__":
    command_line_args = sys.argv
    config = parse_command_line(command_line_args)

    if config is None:
        raise SystemExit("args wrong")


    symbol_list, name_occurrences = parse_file(config.nm_data_file)
    addr2line_process = start_addr2line_process(config.vmlinux_file, config.addr2line_file)

    with open(config.output_file, 'w') as file:
       for obj in symbol_list:
           file.write("{} {} {}\n".format(obj.address, obj.type, obj.name))
           if obj.type == "T" or obj.type == "t":
                if name_occurrences[obj.name]>1 :
                    send_line_to_addr2line(addr2line_process, obj.address)
                    output = fetch_line_from_addr2line(addr2line_process)
                    output = fetch_line_from_addr2line(addr2line_process)
                    decoration = "@" + "".join(["_" if not c.isalnum() else c for c in output.replace(config.linux_base_dir, "")])
                    file.write("{} {} {}\n".format(obj.address, obj.type, obj.name+decoration))

    addr2line_process.stdin.close()
    addr2line_process.stdout.close()
    addr2line_process.stderr.close()
    addr2line_process.wait()
