#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1
# author = felicitychou


# json to file / Sqlite3 / mongodb
# jsonlog
class Output(object):

    def __init__(self, type, filepath):
        self.type = type
        self.filepath = filepath



    def write(self, data):

