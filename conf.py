#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.2

curdir = os.path.split(os.path.realpath(__file__))[0]


docker_conf = {
                "mal_path":'/tmp/sample',
                "code_path":'/tmp/code/',
                "result_path":'/tmp/result/',
                "win_image":'felicitychou/wmas',
                "linux_image":'felicitychou/lmas',
                }


dynamic_conf = {
    "result_path":os.path.join(curdir,'result'),
    "code_path":os.path.join(curdir,'core','code')
    "timeout":30,
}


static_conf = {
    "yara_uncompiled_rules": {
        'namespace1': 'yararules/email/image.yar',
        'namespace2': 'yararules/email/scam.yar',
        'namespace3': 'yararules/email/urls.yar'
    },
    "yara_compiled_rules":"yararules/yara_compiled_rules/"
}
