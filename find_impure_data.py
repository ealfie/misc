#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" find_impure_data.py: Scan object files for impure data
    in BSS or initialized data sections."""

__author__ = "Ezequiel Alfie"
__copyright__ = "Copyright (C) 2014 - Ezequiel Alfie"
__license__ = "GPLv2"


import fnmatch
import os
import subprocess

NON_REENTRANT_SYMBOL_CLASSES = ['d', 'b', 'D', 'B', 'C', 'c']

IGNORE_SYMBOL_LIST = ['std::__ioinit',
    '__gthread_active_p()::__gthread_active_ptr']

OBJECT_FILE_PATTERN = '*.o'


def find_object_files(path):
    """Scan path recursively for filenames
    matching OBJECT_FILE_PATTERN"""
    object_filenames = []
    for root, _, filenames in os.walk(path):
        for filename in fnmatch.filter(filenames, OBJECT_FILE_PATTERN):
            object_filenames.append(os.path.join(root, filename))
    return object_filenames


def scan_object(filename):
    """Scan one filename with nm and looks for symbols in data or bss sections
    it returns a list of tuples, each of which of the form
    (filename, symbol_name, symbol_size)"""

    impure_symbols = []
    nm_process = subprocess.Popen(
        ['nm', '--demangle', '--print-size', '--defined-only', filename],
        stdout=subprocess.PIPE)
    output = nm_process.communicate()[0]
    lines = output.splitlines(True)

    for line in lines:
        try:
            address, size, symbol_type, name = line.split(" ")
        except ValueError:
            continue
        name = name.strip()
        size = int(size, 16)
        address = int(address, 16)

        if name in IGNORE_SYMBOL_LIST:
            continue

        if symbol_type in NON_REENTRANT_SYMBOL_CLASSES:
            impure_symbols.append((filename, name, size))

    return impure_symbols


def scan_all_objects(path):
    """Find object files using find_object_files() and scan each one
    using scan_object(), then print all found symbols"""

    impure_symbols = []
    object_files = find_object_files(path)
    for object_file in object_files:
        impure_symbols += scan_object(object_file)

    for sym in impure_symbols:
        print("%s:%s:%s" % sym)


def run():
    import argparse
    description = 'Scan object files (*.o) for impure data'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('path', help='Path to search for object files')
    args = parser.parse_args()
    scan_all_objects(args.path)


if __name__ == "__main__":
    run()
