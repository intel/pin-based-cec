# Copyright (C) 2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause

import subprocess
import os
import os.path
import re
import argparse
import json
import operator


def load_tainted_address_set(filename):
    tainted_addr_set = set()
    with open(filename, 'r') as f:
        for full_line in f:
            line = full_line.strip()
            if line == "TraceStart" or line == "TraceEnd":
                pass
            else:
                colon_index = line.find(':')
                addr = line[0:colon_index]
                operands = line[colon_index:]
                arrow_index = operands.find('-->')
                read_operands = operands[0:arrow_index]
                # write_operands = operands[arrow_index:]
                if (read_operands.find(".T") >= 0):
                    tainted_addr_set.add(addr)
    return tainted_addr_set


def parse_line(line):
    if line.startswith("IP:"):
        return line[4:]
    elif line.startswith("MemRead:") or line.startswith("MemWrite:"):
        first_space_index = line.find(' ')
        second_space_index = line.find(' ', first_space_index + 1)
        return line[first_space_index+1: second_space_index]
    elif line == "TraceMemStart":
        return None
    elif line == "TraceMemEnd":
        return None
    elif line == "TraceIPStart":
        return None
    elif line == "TraceIPEnd":
        return None
    else:
        print("Unknown line: %s" % line)
        return None


def parse_diff_for_mem(diff_str):
    left_addr_list = []
    right_addr_list = []
    start_index = 0
    last_line = False
    while not last_line:
        end_index = diff_str.find("\n", start_index)
        if end_index == -1:
            line = diff_str[start_index:]
            last_line = True
        else:
            line = diff_str[start_index: end_index]
            start_index = end_index + 1

        if line == "":
            pass
        elif line.startswith('@@') or line.startswith('++') or line.startswith('--'):
            pass
        elif line.startswith('-'):
            left_addr_list.append(parse_line(line[1:]))
        elif line.startswith('+'):
            right_addr_list.append(parse_line(line[1:]))

    return (left_addr_list, right_addr_list)


def parse_diff_for_ip(diff_str):
    left_addr_list = []
    right_addr_list = []
    start_index = 0
    last_line = False
    top_context = True
    while not last_line:
        end_index = diff_str.find("\n", start_index)
        if end_index == -1:
            line = diff_str[start_index:]
            last_line = True
        else:
            line = diff_str[start_index: end_index]
            start_index = end_index + 1

        if line == "":
            pass
        elif line.startswith('@@') or line.startswith('++') or line.startswith('--'):
            top_context = True
        elif line.startswith('-'):
            left_addr_list.append(parse_line(line[1:]))
            top_context = False
        elif line.startswith('+'):
            right_addr_list.append(parse_line(line[1:]))
            top_context = False
        else:
            if top_context:
                left_addr_list.append(parse_line(line[1:]))
                right_addr_list.append(parse_line(line[1:]))

    return (left_addr_list, right_addr_list)


def diff_files_for_mem(filename1, filename2):
    cmd = ["diff", "--speed-large-files", "-U0", filename1, filename2]
    proc = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE)
    return parse_diff_for_mem(proc.stdout.decode("utf-8"))


def diff_files_for_ip(filename1, filename2):
    cmd = ["diff", "--speed-large-files", "-U1", filename1, filename2]
    proc = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE)
    return parse_diff_for_ip(proc.stdout.decode("utf-8"))


def lookup_symbol(symtab, addr):
    for (start, size, name, image_address, image_name) in symtab:
        if (addr >= start) and (addr < start + size):
            return (name, addr - image_address, image_name)
    return ("???", 0, "")


def filter_trace(trace_filename, taint_filename, out_filename):
    tainted_addr_set = load_tainted_address_set(taint_filename)
    with open(out_filename, 'w') as f_out:
        with open(trace_filename, 'r') as f_in:
            for line in f_in:
                addr = parse_line(line.strip())
                if addr is not None and addr in tainted_addr_set:
                    f_out.write(line)


def analyze_all_files_for_mem(trace_path, taint_path, symtab,
                              verbose, result_file):
    ref_filename = "trace0"
    ref_filepath = os.path.join(trace_path, ref_filename)
    ref_taint_filename = "taint0"
    ref_taint_filepath = os.path.join(taint_path, ref_taint_filename)

    if verbose:
        print("Filtering memory reference trace...")

    ref_temp_filepath = os.path.join(trace_path, "temp0")
    filter_trace(ref_filepath, ref_taint_filepath, ref_temp_filepath)

    addr_set = set()
    temp_filepath = os.path.join(trace_path, "tempX")

    with os.scandir(trace_path) as scanner:
        for item in scanner:
            if item.is_file() and item.name != ref_filename and item.name.startswith("trace"):
                if verbose:
                    print("Filtering memory %s..." % item.name)
                trace_filepath = os.path.join(trace_path, item.name)
                trace_index = int(item.name[5:])
                taint_filename = "taint%d" % trace_index
                taint_filepath = os.path.join(taint_path, taint_filename)
                filter_trace(trace_filepath, taint_filepath, temp_filepath)

                if verbose:
                    print("Diffing memory %s..." % item.name)

                (left_tainted_addr_list,
                 right_tainted_addr_list) = diff_files_for_mem(ref_temp_filepath, temp_filepath)

                if len(left_tainted_addr_list) > 0 or len(right_tainted_addr_list) > 0:
                    for addr in left_tainted_addr_list:
                        dot_index = addr.find('.')
                        addr_set.add(int(addr[0:dot_index], 16))
                    for addr in right_tainted_addr_list:
                        dot_index = addr.find('.')
                        addr_set.add(int(addr[0:dot_index], 16))

    print()

    # Cleanup temp files (temp0 and tempX)
    if os.path.isfile(ref_temp_filepath):
        os.remove(ref_temp_filepath)
    if os.path.isfile(temp_filepath):
        os.remove(temp_filepath)

    if len(addr_set) > 0:
        print("Addresses with tainted memory access differences:")
        result_file.write("Addresses with tainted memory access differences:\n")
        for addr in sorted(addr_set):
            (sym_name, offset, image_name) = lookup_symbol(symtab, addr)
            print("%X --> %s (%s @ %X)" % (addr, sym_name, image_name, offset))
            result_file.write("%X --> %s (%s @ %X)\n" % (addr, sym_name, image_name, offset))
    else:
        print("No addresses with tainted memory access differences.")
        result_file.write("No addresses with tainted memory access differences.\n")
    print()


def analyze_all_files_for_ip(trace_path, taint_path, symtab, verbose, result_file):
    ref_filename = "trace0"
    ref_filepath = os.path.join(trace_path, ref_filename)
    ref_taint_filename = "taint0"
    ref_taint_filepath = os.path.join(taint_path, ref_taint_filename)

    if verbose:
        print("Filtering IP reference trace...")

    ref_temp_filepath = os.path.join(trace_path, "temp0")
    filter_trace(ref_filepath, ref_taint_filepath, ref_temp_filepath)

    addr_set = set()
    temp_filepath = os.path.join(trace_path, "tempX")

    with os.scandir(trace_path) as scanner:
        for item in scanner:
            if item.is_file() and item.name != ref_filename and item.name.startswith("trace"):
                if verbose:
                    print("Filtering IP %s..." % item.name)
                trace_filepath = os.path.join(trace_path, item.name)
                trace_index = int(item.name[5:])
                taint_filename = "taint%d" % trace_index
                taint_filepath = os.path.join(taint_path, taint_filename)
                filter_trace(trace_filepath, taint_filepath, temp_filepath)

                if verbose:
                    print("Diffing IP %s..." % item.name)

                (left_tainted_addr_list,
                 right_tainted_addr_list) = diff_files_for_ip(ref_temp_filepath, temp_filepath)

                if len(left_tainted_addr_list) > 0 or len(right_tainted_addr_list) > 0:
                    for addr in left_tainted_addr_list:
                        dot_index = addr.find('.')
                        addr_set.add(int(addr[0:dot_index], 16))
                    for addr in right_tainted_addr_list:
                        dot_index = addr.find('.')
                        addr_set.add(int(addr[0:dot_index], 16))

    print()

    # Cleanup temp files (temp0 and tempX)
    if os.path.isfile(ref_temp_filepath):
        os.remove(ref_temp_filepath)
    if os.path.isfile(temp_filepath):
        os.remove(temp_filepath)

    if len(addr_set) > 0:
        print("Addresses with tainted execution differences:")
        result_file.write("Addresses with tainted execution differences:\n")
        for addr in sorted(addr_set):
            (sym_name, offset, image_name) = lookup_symbol(symtab, addr)
            print("%X --> %s (%s @ %X)" % (addr, sym_name, image_name, offset))
            result_file.write("%X --> %s (%s @ %X)\n" % (addr, sym_name, image_name, offset))
    else:
        print("No addresses with tainted execution differences.")
        result_file.write("No addresses with tainted execution differences.\n")
    print()


def parse_image_map(image_map_filename, verbose=False):
    global_symtab = []
    with open(image_map_filename, 'r') as image_map_file:
        image_map = json.load(image_map_file)
    for (image_name, image_offset_str) in image_map.items():
        image_offset = int(image_offset_str, 16)
        symtab = parse_symbols(image_name, offset=image_offset, verbose=verbose)
        global_symtab.extend(symtab)
    global_symtab.sort(key=operator.itemgetter(0))
    return global_symtab


def parse_symbols(image_name, offset=0, verbose=False):
    cmd = ["nm", "-nS", "--defined-only", image_name]
    proc = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    nm_output = proc.stdout.decode("utf-8")

    if verbose:
        print(proc.stderr.decode("utf-8"))

    line_re = re.compile("([0-9a-f]+) ([0-9a-f]+) . (.+)")
    symtab = []
    for line in nm_output.split("\n"):
        m = line_re.match(line)
        if m is not None:
            start = int(m.group(1), 16) + offset
            size = int(m.group(2), 16)
            name = m.group(3)
            symtab.append((start, size, name, offset, image_name))
    return symtab


def branch_check_file(filename):
    addr_set = set()
    line_re = re.compile(r"([0-9a-f]+)\.[0-9a-f]+\: \[(.+)\] --> \[(.+)\]")
    with open(filename, 'r') as f_in:
        for line in f_in:
            m = line_re.match(line.strip())
            if m is not None:
                addr = int(m.group(1), 16)
                read_operands = m.group(2)
                write_operands = m.group(3)
                if read_operands.find('.T') != -1 and write_operands.find('REG(rip)') != -1:
                    addr_set.add(addr)

    return addr_set


def branch_check_all_files(taint_path, symtab, verbose):
    addr_set = set()

    with os.scandir(taint_path) as scanner:
        for item in scanner:
            if item.is_file():
                file_addr_set = branch_check_file(os.path.join(taint_path, item.name))
                addr_set.update(file_addr_set)

    if len(addr_set) > 0:
        print("Tainted branches:")
        for addr in sorted(addr_set):
            (sym_name, offset, image_name) = lookup_symbol(symtab, addr)
            print("%X --> %s (%s @ %X)" % (addr, sym_name, image_name, offset))
    else:
        print("No tainted branches.")

    print()


def main(verbose, branch_check, result_filename):
    symtab = parse_image_map("image_map", verbose=verbose)

    with open(result_filename, 'w') as result_file:
        analyze_all_files_for_mem("memtrace", "taint", symtab, verbose, result_file)
        analyze_all_files_for_ip("iptrace", "taint", symtab, verbose, result_file)

    if branch_check:
        branch_check_all_files("taint", symtab, verbose)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Process some traces.")
    parser.add_argument("result_file", help="Name of output file to print to (as well as stdout).")
    parser.add_argument("--verbose", default=False, action='store_true')
    parser.add_argument("--branch", default=False, action='store_true',
                        help="Report any conditional branches that depend on secret data (experimental).")

    args = parser.parse_args()
    main(args.verbose, args.branch, args.result_file)
