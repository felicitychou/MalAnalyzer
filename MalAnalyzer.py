#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.3

import os
import subprocess
import hashlib
from optparse import OptionParser

# pip install python-magic
import magic
#import yara

#from conf import platform_conf
#from static_analyze import static_analyze
#from dynamic_analyze import dynamic_analyze



def get_file_basic_info(filepath):
    '''
    return {filename,filetype,filesize(Byte),filemd5sum}
    '''
    filename = os.path.basename(filepath)
    filetype = magic.from_file(filepath)
    filesize = int(os.path.getsize(filepath))
    filemd5sum = md5sum(filepath)

    return filename,filetype,filesize,filemd5sum

def md5sum(filepath):
    with open(filepath, 'rb') as f:
        m = hashlib.md5(f.read())
    return m.hexdigest()


def analyze(filepath):
    basic_info = get_file_basic_info(filepath)
    static_analyze_result = static_analyze(filepath)
    dynamic_analyze_result = dynamic_analyze(filepath,filetype)



def main():
    parser = OptionParser(version = "%prog 3.0")

    parser.add_option("-f", "--file", dest="filepath", help="Malcode filepath")
    parser.add_option("-m", "--mode", dest="mode", help="Malcode Analyze mode: basic/static/dynamic/all",default='all')
    #parser.add_option("-q", "--quiet", action="store_false", dest="verbose", default=True, help="don't print status messages to stdout")  
  
    (options, args) = parser.parse_args()  

    if options.filepath:
        filepath = options.filepath
    if options.mode:
        mode = options.mode




if __name__ == '__main__':
    #main()
    print get_file_basic_info("test/1e722fb96a6133ba8ce70b68f51c5cb96b94b0d4491c9f28543755351147da3a")
    print get_file_basic_info("test/af4d62414d6548fe6e3df537f073c6b076d963604a2a9f8a6cdaeeef6918c7ee")