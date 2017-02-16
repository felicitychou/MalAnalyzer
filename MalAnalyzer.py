#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.3

import os
import subprocess
from optparse import OptionParser

import magic
import yara

from conf import platform_conf
from static_analyze import static_analyze
from dynamic_analyze import dynamic_analyze


def get_file_basic_info(filepath):
    '''
    return {filename,filetype,filesize(Byte),filemd5sum}
    '''
    filename = os.path.basename(filepath)
    filetype = magic.from_file(filepath)
    filesize = int(os.path.getsize(filename))
    filemd5sum = md5sum(filepath)

    return filename,filetype,filesize,filemd5sum

def md5sum(filepath):
    with open(filepath, 'rb') as f:
        m = hashlib.md5(f.read())
    return m.hexdigest()


def analyze(filepath):
    basic_info = get_file_basic_info(filename)
    static_analyze_result = static_analyze(filename)
    dynamic_analyze_result = dynamic_analyze(filename,filetype)



def main():
    parser = OptionParser(version = "%prog 3.0")

    parser.add_option("-f", "--file", dest="filepath", help="Malcode filepath")
    #parser.add_option("-o", "--output",dest="")
    #parser.add_option("-q", "--quiet", action="store_false", dest="verbose", default=True, help="don't print status messages to stdout")  
  
    (options, args) = parser.parse_args()  

    if options.filepath:
        filepath = options.filepath



