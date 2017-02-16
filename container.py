#!/usr/bin/env Python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.2
# for docker 1.12
# Docker SDK for Python :pip install docker (version>=2.0)


import time
import os

from docker import DockerClient

from conf import docker_conf

class Container(object):

    def __init__(self):
        #self.cli = DockerClient(base_url='unix://var/run/docker.sock')
        self.client = docker.from_env()
        self.mal_path = docker_conf['mal_path']
        self.code_path = docker_conf['code_path']
        self.result_path = docker_conf['result_path']
        self.win_image = docker_conf['win_image']
        self.linux_image = docker_conf['linux_image']

    def start(self,name,mal_path,timeout,platform,code_path):
        command = 'python %s -f %s -t %d' % (os.path.join(self.code_path,'analyze.py'),self.mal_path,timeout)
        if platform == 'win':
            image = self.win_image
            #host_config=self.cli.create_host_config(binds={mal_path: {'bind': self.mal_path,'mode': 'ro',},
            #                                          code_path: {'bind': self.code_path,'mode': 'rw',}})
            config = {"name":name,"volumes":{mal_path: {'bind': self.mal_path,'mode': 'ro'},code_path:{'bind': self.code_path,'mode': 'rw'}},"detach":True}
        elif platform == 'linux':
            image = self.linux_image
            #host_config = self.cli.create_host_config(binds={mal_path: {'bind': self.mal_path,'mode': 'ro',},
            #                                                 code_path: {'bind': self.code_path,'mode': 'rw',}},
            #                                          security_opt=['seccomp=unconfined'])
            config = {"name":name,"volumes":{mal_path: {'bind': self.mal_path,'mode': 'ro'},code_path:{'bind': self.code_path,'mode': 'rw'}},"detach":True,"security_opt":['seccomp=unconfined']}
        else:
            #return False,None
            return None
        #container = self.cli.create_container(name=name,image=image, command=command, volumes=[self.mal_path, self.code_path], host_config=host_config)
        #response = self.cli.start(container=container.get('Id'))
        #if response is None:
        #    return True,container
        #else:
        #    return False,container
        try:
            container = self.client.containers.run(image=image,command=command,**config)
            return container
        except Exception as e:
            raise e
        
    def cp(self,container,srcpath,dstpath):
        #strm, stat = self.cli.get_archive(container, srcpath)
        strm, stat = container.get_archive(srcpath)
        with open(dstpath, 'wb') as f:
            f.write(strm.read())
        return stat

    def ifrunning(self,container):
        #if self.cli.containers(filters={"status":"running","id":container.get('Id')}):
    #        return True
    #    else:
    #        return False
        return (True if container.status == 'running' else False)

    def check(self,container,timeout):
        #wait = -5
        wait = 0
        while (wait < timeout and self.ifrunning(container)):
            time.sleep(10)
            wait += 10
        if self.ifrunning(container):
            #self.cli.kill(container)
            container.stop(timeout=5)

    def delete(self,container):
        #self.cli.remove_container(container=container,force=True)
        container.remove(force=True)

    def analyze(self,name,mal_path,timeout,result_path,platform,code_path):
        try:
            #result,container = self.start(name=name,mal_path=mal_path,timeout=timeout,platform=platform,code_path=code_path)
            container = self.start(name=name,mal_path=mal_path,timeout=timeout,platform=platform,code_path=code_path)
            #if result:
            if container:
                self.check(container=container,timeout=timeout)
                stat = self.cp(container,srcpath=self.result_path,dstpath=result_path)
            else:
                return False
        except Exception as e:
            print Exception,e
            return False
        finally:
            if container:
                self.delete(container)

#if __name__ == '__main__':
#    con = Container()
#    g_curdir = os.path.split(os.path.realpath(__file__))[0]
    #con.analyze(name='linuxtest',mal_path=os.path.join(g_curdir,'sample1'),timeout=30,
    #            result_path='linuxtest.tar',platform='linux',code_path=os.path.join(g_curdir,'analyze','linux'))

#    con.analyze(name='wintest',mal_path=os.path.join(g_curdir,'sample2'),timeout=30,
#                result_path='winetest.tar',platform='win',code_path=os.path.join(g_curdir,,'analyze','win'))

if __name__ == '__main__':
    # wine --security-opt seccomp:unconfined
    con = Container()
    # win test 1e722fb96a6133ba8ce70b68f51c5cb96b94b0d4491c9f28543755351147da3a
    filename = '1e722fb96a6133ba8ce70b68f51c5cb96b94b0d4491c9f28543755351147da3a'
    con.analyze(name=filename,mal_path=os.path.join('test',filename),timeout=30,
                result_path='%s.tar'%(filename,),platform='win',code_path='container_code/')

    # linux test af4d62414d6548fe6e3df537f073c6b076d963604a2a9f8a6cdaeeef6918c7ee
    filename = 'af4d62414d6548fe6e3df537f073c6b076d963604a2a9f8a6cdaeeef6918c7ee'
    con.analyze(name=filename,mal_path=os.path.join('test',filename),timeout=30,
                result_path='%s.tar'%(filename,),platform='linux',code_path='container_code/')



