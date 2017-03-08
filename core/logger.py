#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1
# author = felicitychou

import logging

class Logger(object):
    
    def __init__(self, logname = "log.txt", loglevel = logging.DEBUG, loggername = "logger"):
        
        self.logger = logging.getLogger(loggername)
        self.logger.setLevel(loglevel)
        
        format = '%(asctime)s %(filename)s: %(levelname)s %(message)s'
        datefmt='%Y/%m/%d %H:%M:%S'
        formatter = logging.Formatter(format,datefmt)       
        
        fh = logging.FileHandler(logname)
        fh.setLevel(loglevel)
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

        ch = logging.StreamHandler()
        ch.setLevel(loglevel)
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

logger = Logger().logger