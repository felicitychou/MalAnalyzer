#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1

from optparse import OptionParser

from core.basic_analyze import BasicAnalyzer
from core.static_analyze import StaticAnalyzer
from core.dynamic_analyze import DynamicAnalyzer
from core.logger import Logger
from core.output import 


def analyze(filepath):

    basic_analyzer = BasicAnalyzer()
    static_analyzer = StaticAnalyzer()
    dynamic_analyzer = DynamicAnalyzer()
    outputter = Outputter()





def main():
    usage = "usage: %prog [options] filepath"
    parser = OptionParser(version = "%prog 1.0")

    parser.add_option("-f", "--file", dest="filepath", help="Malcode filepath")
    #parser.add_option("-m", "--mode", dest="mode", help="Malcode Analyze mode: basic/static/dynamic/all",default='all')

    (options, args) = parser.parse_args()  

    if options.filepath:
        filepath = options.filepath
    if options.mode:
        mode = options.mode




if __name__ == '__main__':
    main()
