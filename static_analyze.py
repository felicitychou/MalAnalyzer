#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1
# author = felicitychou

import subprocess
import yara

from conf import static_conf

class StaticAnalyzer(object):

    def __init__(self,filepath):
        self.filepath = filepath


    # yara scan
    def yara_scan(self, rulesfile):
        rules = yara.compile(rulesfile)
        matches = rules.match(self.filepath)
        return matches

    def vt_scan(self):
        pass

    def clamav_scan(self):
        pass

    def run(self):

        # yara_scan
        yara_scan_result = self.yara_scan(rulesfile=static_conf['yararules'])

        # VT_scan
        vt_scan_result = self.vt_scan()

        #ClamAV_scan




