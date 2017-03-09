#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1
# author = felicitychou

import os
from basic_analyze import BasicAnalyzer
from logger import Logger

filepath = ""
logger = Logger(logname = "%s.txt" % os.path.splitext(__file__)[0])
basic_analyzer = BasicAnalyzer(filepath = filepath,logger = logger).logger

print(basic_analyzer.run())