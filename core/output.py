#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1
# author = felicitychou

import json

from conf import output_conf
from logger import logger
from core.basic_analyze import BasicAnalyzer
from core.static_analyze import StaticAnalyzer
from core.dynamic_analyze import DynamicAnalyzer

# file ：json markdown
# database：Sqlite3 / mongodb

class OutputJson(object):

    def __init__(self):
        self.jsonpath = output_conf['json']['path']
        #self.log = logger

    def write(self,analyzers):
        json_dict = {}

        for analyzer in analyzers:
            result = {}
            if isinstance(analyzer,BasicAnalyzer):
                analyzer_type = 'basic'
            elif isinstance(analyzer,StaticAnalyzer):
                analyzer_type = 'static'
            elif isinstance(analyzer,DynamicAnalyzer):
                analyzer_type = 'dynamic'
            else:
                pass
            json_dict[analyzer_type]  = dict(zip(analyzer.output(),[getattr(analyzer,item,None) for item in analyzer.output()]))

        with open(self.jsonpath,'wb') as fw:
            json.dump(json_dict,fw)


class OutputHandle(object):
    """docstring for OutputHandle"""
    def __init__(self):
        pass


    def write(self, data):
        pass


        
