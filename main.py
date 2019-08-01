#!/usr/bin/python2 -u
# -*- coding: utf-8 -*-

from __future__ import print_function
import argparse
import sys
import pexpect
import colorama
import re

# Realloc (r) and calloc (c) missing
patterns_trace = {
    "m": r"#m:(?P<pointer>0x[0-9a-zA-Z]+);(?P<caller>0x[0-9a-zA-Z]+)-(?P<bytes>[0-9]+)",
    "f": r"#f:(?P<return>0x[0-9a-zA-Z]+);(?P<caller>0x[0-9a-zA-Z]+)-(?P<pointer>0x[0-9a-zA-Z]+)"
}

# Global variable to store the memory allocations
memory_allocations = {}


def get_caller_info(caller_address, symbol_file, max_directory_depth, tool):
    # Addr2line
    if tool == "addr2line":
        addr2line = pexpect.spawn("arm-none-eabi-addr2line -pfiaC -e " + symbol_file + " " +
                                  caller_address)
        addr2line.logfile = None
        match = addr2line.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=2)
        if match == 0:
            return addr2line.before.strip()

    # GDB
    elif tool == "gdb":
        gdb = pexpect.spawn("arm-none-eabi-gdb --batch " + symbol_file +
                            " -ex \"set listsize 1\" -ex \"l *" + caller_address + "\"")
        gdb.logfile = None
        match = gdb.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=2)
        if match == 0:
            output_filtered = gdb.before.strip()
            components = re.match(
                r".*(?P<address>0x[0-9a-z]+) is in (?P<function>.*) \((?P<file>.*):(?P<line>[0-9]+)\)\.\s*?\n[0-9]+\s+(?P<code>(\s*\S*)*)",
                output_filtered)
            if components is not None:
                return {
                    "address": components.group('address'),
                    "function": components.group('function'),
                    "file": components.group('file'),
                    "line": components.group('line'),
                    "code": components.group('code')
                }
            else:
                print("arm-none-eabi-gdb --batch " + symbol_file +
                      " -ex \"set listsize 1\" -ex \"l *" + caller_address + "\"")
                return {
                    "address": caller_address,
                    "function": "??",
                    "file": "??",
                    "line": "??",
                    "code": ""
                }


def print_code_info(code_info, max_directory_depth):
    file_path = code_info["file"]
    if max_directory_depth >= 0:
        tree = file_path.split("/")
        file_path = "/".join(tree[-(max_directory_depth + 1):])

    return (colorama.Style.RESET_ALL + colorama.Fore.RED + code_info["function"] +
            colorama.Style.RESET_ALL + " (" + colorama.Fore.GREEN + file_path +
            colorama.Style.RESET_ALL + ":" + colorama.Fore.BLUE + code_info["line"] + " " +
            colorama.Fore.YELLOW + code_info["code"] + colorama.Style.RESET_ALL + ")")


def print_call_stack_info(call_stack, symbol_file, max_directory_depth, tool):
    memory_allocated = 0
    memory_freed = 0

    for unfiltered_line in call_stack:
        line = unfiltered_line.strip()

        if len(line) > 2 and line[0] == "#" and (line[1] == "m" or line[1] == "r" or
                                                 line[1] == "c" or line[1] == "f"):
            # Get the components of the trace
            components = re.match(patterns_trace[line[1]], line)
            if components is not None:
                caller_info = get_caller_info(
                    components.group("caller"), symbol_file, max_directory_depth, tool)
                # Malloc case
                if line[1] == "m":
                    # Add allocations to the list
                    memory_allocations[components.group("pointer")] = {
                        "bytes": int(components.group("bytes")),
                        "freed": False,
                        "alloc_info": caller_info
                    }
                    memory_allocated = memory_allocated + int(components.group("bytes"))

                # Free case
                elif line[1] == "f":
                    # Add allocations to the list
                    if components.group("pointer") in memory_allocations:
                        memory_allocations[components.group("pointer")]["freed"] = True
                        memory_allocations[components.group("pointer")]["free_info"] = caller_info
                    memory_freed = memory_freed + memory_allocations[components.group(
                        "pointer")]["bytes"]

    # Print information about the allocated data
    for pointer, allocation in memory_allocations.items():
        print(
            "-------------------------------\r\nPointer {0}\r\nFunction {1}\r\n{2} bytes".format(
                pointer, print_code_info(allocation["alloc_info"], max_directory_depth),
                allocation["bytes"]),
            end='')

        if allocation["freed"] is True:
            print("\r\nFreed by {0}".format(
                print_code_info(allocation["free_info"], max_directory_depth)))
        else:
            print("\r\nNot freed")

    print("{0} bytes allocated in total, of which {1} have been freed during the execution".format(
        memory_allocated, memory_freed))


if __name__ == "__main__":
    colorama.init()

    # Define an argument parser and parse the arguments
    parser = argparse.ArgumentParser("Decode the backtrace given as argument")
    parser.add_argument(
        "--symbol_file",
        help=
        "Path to the symbol file corresponding to the executable that has been executed to produce the heap tracing",
        type=open)
    parser.add_argument(
        "--backtrace", help="Backtrace printed by the ESP32", type=argparse.FileType('r'))
    parser.add_argument(
        "--max_directory_depth",
        help=
        "Set the maximum directory depth when displaying file paths, default to -1 (complete file path)",
        default=-1,
        type=int)
    parser.add_argument(
        "--tool",
        help="Specify the tool to use for address decoding",
        choices=['addr2line', 'gdb'],
        default='gdb')
    args = parser.parse_args()

    if args.backtrace is not None and args.symbol_file is not None:
        symbol_file = args.symbol_file.name
        print_call_stack_info(args.backtrace.readlines(), symbol_file, args.max_directory_depth,
                              args.tool)
