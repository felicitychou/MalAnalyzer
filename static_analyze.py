#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.3





# get pe info


# get elf info


# get strings unicode and ascii
def get_strings(filepath):
    # windows
    # strings.exe https://technet.microsoft.com/en-us/sysinternals/bb897439.aspx

    #linux
    ascii_strings = subprocess.check_output(["strings", "-a", self.file])
    unicode_strings = subprocess.check_output(["strings", "-a", "-el", self.file])
    return ascii_strings,unicode_strings

# yara scan
def yara_scan(filepath,rulesfile):
    rules = yara.compile(rulesfile,rulesfile)
    matches = rules.match(filepath)
    return matches


def static_analyze(filepath):
    pass