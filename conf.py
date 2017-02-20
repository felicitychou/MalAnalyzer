#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.2

docker_conf = {
                "mal_path":'/tmp/sample',
                "code_path":'/tmp/code/',
                "result_path":'/tmp/result/',
                "win_image":'felicitychou/wmas',
                "linux_image":'felicitychou/lmas',
                }

#platform_conf = {
#    "win":{"code_path":"win"},
#    "linux":{"code_path":"linux"}
#}
dynamic_conf = {
    "timeout":30,


}

static_conf = {
    "yararules":'yara',


}