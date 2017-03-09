#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.2

import os

curdir = os.path.dirname(os.path.split(os.path.realpath(__file__))[0])


docker_conf = {
                "mal_path":'/tmp/sample',
                "code_path":'/tmp/code/',
                "result_path":'/tmp/result/',
                "win_image":'felicitychou/wmas',
                "linux_image":'felicitychou/lmas',
                }


dynamic_conf = {
    "result_path":os.path.join(curdir,'result'),
    "code_path":os.path.join(curdir,'core','code'),
    "timeout":30,
}


static_conf = {
    "yara_scan":True,
    "yara_uncompiled_rules": {
        'x': os.path.join(curdir,'data','yara_uncompiled_rules/x.yar'),
        'y': os.path.join(curdir,'data','yara_uncompiled_rules/y.yar'),
        'z': os.path.join(curdir,'data','yara_uncompiled_rules/z.yar'),
    },
    "yara_compiled_rules":os.path.join(curdir,'data','yara_compiled_rules'),
    "vt_scan":True,
    "vt_apikey":"",
    "clamav_scan":False,
}

basic_conf = {
    "UPX_path":"/usr/bin/upx",
    "PEidSign_path":os.path.join(curdir,'data','userdb.txt'),
}