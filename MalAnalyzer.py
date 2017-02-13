#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.3

import os
from optparse import OptionParser

import magic

from conf import platform_conf



def get_file_type(filepath):
    return  magic.from_file(filepath)

def get_file_basic_info(filepath):
    '''
    return {filename,filetype,filesize(Byte)}
    '''
    filename = os.path.basename(filepath)
    filetype = get_file_type(filepath)
    filesize = int(os.path.getsize(filename))

    return filename,filetype,filesize

def yara_scan(filepath):
    pass


def static_analyze(filepath):
    pass

def get_platform(filetype):
    pass 

def dynamic_analyze(filepath,filetype):

    platform = get_platform(filetype)
    if platform:
        container = Container()
        container.analyze(name=taskid,mal_path=filepath,timeout=timeout,
        result_path=result_path,platform=platform,code_path=platform_conf[platform]['code_path'])
    else:
        #logger.info("Can't handle type: %s" % task['type'])
        print "not support"

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



