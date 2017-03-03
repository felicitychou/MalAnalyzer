#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1
# author = felicitychou
# for docker 1.12
# Docker SDK for Python :pip install docker (version>=2.0)


import time
import os

import docker

from conf import docker_conf
from logger import logger

class Container(object):

    def __init__(self,logger):
        #self.cli = DockerClient(base_url='unix://var/run/docker.sock')
        self.client = docker.from_env()
        self.mal_path = docker_conf['mal_path']
        self.code_path = docker_conf['code_path']
        self.result_path = docker_conf['result_path']
        self.win_image = docker_conf['win_image']
        self.linux_image = docker_conf['linux_image']
        self.logger = logger

    def start(self,name,mal_path,timeout,platform,code_path):
        command = 'python %s -f %s -t %d -m %s' % (os.path.join(self.code_path,'analyze.py'),self.mal_path,timeout,platform)
        
        if platform == 'win':
            image = self.win_image
            config = {"name":name,"volumes":{mal_path: {'bind': self.mal_path,'mode': 'ro'},code_path:{'bind': self.code_path,'mode': 'rw'}},"detach":True}
        elif platform == 'linux':
            image = self.linux_image
            config = {"name":name,"volumes":{mal_path: {'bind': self.mal_path,'mode': 'ro'},code_path:{'bind': self.code_path,'mode': 'rw'}},"detach":True,"security_opt":['seccomp=unconfined']}
        else:
            return None

	self.logger.debug("image:%s command:%s config:%s" % (image,command,config))
        try:
            container = self.client.containers.run(image=image,command=command,**config)
            return container
        except Exception as e:
            #self.logger.exception('%s: %s' % (Exception,e))
            raise e
        
    def cp(self,container,srcpath,dstpath):
        #strm, stat = self.cli.get_archive(container, srcpath)
        strm, stat = container.get_archive(srcpath)
        with open(dstpath, 'wb') as f:
            f.write(strm.read())
        self.logger.debug("copy from %s:%s to %s" % (container.id,srcpath,dstpath))
        return stat

    def ifrunning(self,container):
        container.reload()
        return (True if container.status == 'running' else False)

    def check(self,container,timeout):
        wait = 0 
        while (wait <= timeout and self.ifrunning(container)):
            self.logger.debug("Check container %s status: %s" % (container.id,container.status,))
            time.sleep(1)
            wait += 1
            self.logger.debug("Wait container %s %s" % (container.id,wait))
	
        if self.ifrunning(container):
            container.stop(timeout=1)
            self.logger.info("Stop container %s." % (container.id,))

        self.logger.info("Container %s has stopped." % (container.id,))

    def delete(self,container):
        container.remove(force=True)
        self.logger.info("Container %s has removed." % (container.id,))

    def analyze(self,name,mal_path,timeout,result_path,platform,code_path):
        container = None
        try:
            self.logger.info("Start Container.")
            container = self.start(name=name,mal_path=mal_path,timeout=timeout,platform=platform,code_path=code_path)
            if isinstance(container,docker.models.containers.Container):
                self.logger.info("RUN container %s successfully." % (container.id,))
                self.check(container=container,timeout=timeout)
                stat = self.cp(container,srcpath=self.result_path,dstpath=result_path)
            else:
                return False
        except Exception as e:
            self.logger.exception('%s: %s' % (Exception,e))
        finally:
            if isinstance(container,docker.models.containers.Container):
                self.logger.info("Remove container %s." % (container.id))
                self.delete(container)

#if __name__ == '__main__':
#    con = Container()
#    g_curdir = os.path.split(os.path.realpath(__file__))[0]
    #con.analyze(name='linuxtest',mal_path=os.path.join(g_curdir,'sample1'),timeout=30,
    #            result_path='linuxtest.tar',platform='linux',code_path=os.path.join(g_curdir,'analyze','linux'))

#    con.analyze(name='wintest',mal_path=os.path.join(g_curdir,'sample2'),timeout=30,
#                result_path='winetest.tar',platform='win',code_path=os.path.join(g_curdir,,'analyze','win'))

if __name__ == '__main__':
    logger = Logger().logger
    con = Container(logger)
    # win test 1e722fb96a6133ba8ce70b68f51c5cb96b94b0d4491c9f28543755351147da3a
    filename = '1e722fb96a6133ba8ce70b68f51c5cb96b94b0d4491c9f28543755351147da3a'
    con.analyze(name=filename,mal_path=os.path.join('/home/antiylab/mal/test',filename),timeout=30,
                result_path='%s.tar'%(filename,),platform='win',code_path='/home/antiylab/mal/container_code/')

    # linux test af4d62414d6548fe6e3df537f073c6b076d963604a2a9f8a6cdaeeef6918c7ee
    filename = 'af4d62414d6548fe6e3df537f073c6b076d963604a2a9f8a6cdaeeef6918c7ee'
    con.analyze(name=filename,mal_path=os.path.join('/home/antiylab/mal/test',filename),timeout=30,
                result_path='%s.tar'%(filename,),platform='linux',code_path='/home/antiylab/mal/container_code/')



