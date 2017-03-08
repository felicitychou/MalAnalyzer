#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1
# author = felicitychou

import json

from core.conf import output_conf
from logger import logger


# file ：json markdown
# database：Sqlite3 / mongodb

class OutputJson(object):

    def __init__(self):
        self.path = output_conf['json']['path']
        self.handle = self.open(path=self.path)
        self.log = logger

    def open(self, path):
        if not os.path.exists(path):
            self.handle = open(path,'wb+')
        else:
            self.log.error("Json Path Error: %s exists." % (path,))

    def write(self,analyzer):

        if isinstance(analyzer,)

        self.handle()
        json.
        pass





class OutputHandle(object):
    """docstring for OutputHandle"""
    def __init__(self):

        pass


    def write(self, data):
        for item in 


        
