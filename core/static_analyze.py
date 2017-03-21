#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1
# author = felicitychou

import os

import yara
import requests

from conf import static_conf

class StaticAnalyzer(object):

    def __init__(self,filepath,hash,logger):
        self.filepath = filepath
        self.logger = logger
        self.hash = hash
        self.run()

    def run(self):
        try:

            if static_conf['yara_scan']:
                # yara_scan
                self.yara_scan()
            if static_conf['vt_scan'] and static_conf['vt_apikey']:
                # VT_scan
                self.vt_scan()
            if static_conf['clamav_scan']:
                # ClamAV_scan
                self.clamav_scan()
        except Exception as e:
            self.logger.exception('%s: %s' % (Exception, e))
    
    # output list
    def output(self):
        return ['yara_scan_result','vt_scan_result']      

    # yara scan
    def yara_scan(self):
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
        try:
            self.yara_scan_result = []
            yara_uncompiled_rules = static_conf["yara_uncompiled_rules"]
            yara_compiled_rules = static_conf["yara_compiled_rules"]
            yara_rules_list = []
            # load rules
            if yara_uncompiled_rules:
                yara_rules_list.append(yara.compile(filepaths = yara_uncompiled_rules))
            if yara_compiled_rules:
                yara_rules_list.extend([yara.load(os.path.join(yara_compiled_rules,item)) for item in os.listdir(yara_compiled_rules)])
            # match yara rules
            for rules in yara_rules_list:
                matches = rules.match(self.filepath)
                self.yara_scan_result.extend([{"namespace":match.namespace,"rule":match.rule,"meta":match.meta} for match in matches])
        except Exception as e:
            self.logger.exception('%s: %s' % (Exception, e))
            

    def vt_scan(self):
        '''
        {
 'response_code': 1,
 'verbose_msg': 'Scan finished, scan information embedded in this object',
 'resource': '99017f6eebbac24f351415dd410d522d',
 'scan_id': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724',
 'md5': '99017f6eebbac24f351415dd410d522d',
 'sha1': '4d1740485713a2ab3a4f5822a01f645fe8387f92',
 'sha256': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c',
 'scan_date': '2010-05-15 03:38:44',
 'positives': 40,
 'total': 40,
 'scans': {
    'nProtect': {'detected': true, 'version': '2010-05-14.01', 'result': 'Trojan.Generic.3611249', 'update': '20100514'},
    'CAT-QuickHeal': {'detected': true, 'version': '10.00', 'result': 'Trojan.VB.acgy', 'update': '20100514'},
    'McAfee': {'detected': true, 'version': '5.400.0.1158', 'result': 'Generic.dx!rkx', 'update': '20100515'},
    'TheHacker': {'detected': true, 'version': '6.5.2.0.280', 'result': 'Trojan/VB.gen', 'update': '20100514'},
    .
    .
    .
    'VirusBuster': {'detected': true, 'version': '5.0.27.0', 'result': 'Trojan.VB.JFDE', 'update': '20100514'},
    'NOD32': {'detected': true, 'version': '5115', 'result': 'a variant of Win32/Qhost.NTY', 'update': '20100514'},
    'F-Prot': {'detected': false, 'version': '4.5.1.85', 'result': null, 'update': '20100514'},
    'Symantec': {'detected': true, 'version': '20101.1.0.89', 'result': 'Trojan.KillAV', 'update': '20100515'},
    'Norman': {'detected': true, 'version': '6.04.12', 'result': 'W32/Smalltroj.YFHZ', 'update': '20100514'},
    'TrendMicro-HouseCall': {'detected': true, 'version': '9.120.0.1004', 'result': 'TROJ_VB.JVJ', 'update': '20100515'},
    'Avast': {'detected': true, 'version': '4.8.1351.0', 'result': 'Win32:Malware-gen', 'update': '20100514'},
    'eSafe': {'detected': true, 'version': '7.0.17.0', 'result': 'Win32.TRVB.Acgy', 'update': '20100513'}
  },
 'permalink': 'https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/'
}
        '''
        try:
            params = {'apikey': static_conf['vt_apikey'], 'resource': self.hash}
            headers = {
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "gzip,  My Python requests library example client or username"
            }
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                    params = params, headers = headers)
            self._parse_vt_report(vt_report = response.json())
        except Exception as e:
            self.logger.exception('%s: %s' % (Exception, e))
            


    def _parse_vt_report(self,vt_report):
        try:
            if vt_report['response_code'] == 1:
                self.vt_scan_result = {}
                self.vt_scan_result['scan_date'] = vt_report['scan_date']
                self.vt_scan_result['positives'] = vt_report['positives']
                self.vt_scan_result['total'] = vt_report['total']
                # self.vt_scan_result['scans'] = vt_report['scans']
                # only save detected scans
		        self.vt_scan_result['scans'] = {}
                for key,item in vt_report['scans'].iteritems():
                    if item['detected']:
                        self.vt_scan_result['scans'][key] = item
                    else:
                        pass	
                self.vt_scan_result['permalink'] = vt_report['permalink']
            else:
                self.vt_scan_result = None
        except Exception as e:
            self.logger.exception('%s: %s' % (Exception, e))
            

    def clamav_scan(self):
        pass

    def get_yara_scan_result(self):
        return getattr(self,'yara_scan_result',None)

    def get_vt_scan_result(self):
        return getattr(self,'vt_scan_result',None)

