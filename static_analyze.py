#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1
# author = felicitychou

import subprocess
import os
import yara

from conf import static_conf

class StaticAnalyzer(object):

    def __init__(self,filepath):
        self.filepath = filepath
        self.yara_scan_result = []


    # yara scan
    '''
    {
  'tags': ['foo', 'bar'],
  'matches': True,
  'namespace': 'default',
  'rule': 'my_rule',
  'meta': {},
  'strings': [(81L, '$a', 'abc'), (141L, '$b', 'def')]
}
    '''
    def yara_scan(self):
        yara_uncompiled_rules = static_conf["yara_uncompiled_rules"]
        yara_compiled_rules = static_conf["yara_compiled_rules"]
        yara_rules_list = []
        # load rules
        if yara_uncompiled_rules:
            yara_rules_list.append(yara.compile(filepaths = yara_uncompiled_rules))
        if yara_compiled_rules:
            yara_rules_list.extend([yara.load(os.path.join(yara_compiled_rules,item)) for item in os.listdir(yara_compiled_rules)])
        # match yara rule
        for rules in yara_rules_list:
            matches = rules.match(self.filepath)
            self.yara_scan_result.extend([{"namespace":match.namespace,"rule":match.rule} for match in matches])
        return self.yara_scan_result


    def vt_scan(self):
        pass

    def clamav_scan(self):
        pass

    def run(self):

        # yara_scan
        self.yara_scan()

        # VT_scan
        #vt_scan_result = self.vt_scan()

        #ClamAV_scan

    def get_yara_scan_result(self):
        return self.yara_scan_result




if __name__ == '__main__':
    filepath = ''
    static_analyzer = StaticAnalyzer(filepath = filepath)
    static_analyzer.run()
    yara_scan_result = static_analyzer.get_yara_scan_result()
    print yara_scan_result
