# MalAnalyzer 测试

1. container_code/analyze.py

   ### linux

   - A终端：运行容器

   ```shell
   docker run -it --security-opt seccomp:unconfined felicitychou/lmas
   CONTAINER_ID#root:
   ```

   - B终端：将样本与分析脚本拷贝进容器

   ```shell
   docker cp analyze.py CONTAINERID:/home/
   docker cp LINUX_sample CONTAINERID:/tmp/sample
   ```

   - A终端：运行分析脚本，查看结果/tmp/result

   ```shell
   python /home/analyze.py -f /tmp/sample -m linux
   ...
   ll /tmp/result
   ```

   ​

   win

   - A终端：运行容器

   ```shell
   docker run -it felicitychou/wmas
   CONTAINER_ID#root:
   ```

   - B终端：将样本与分析脚本拷贝进容器

   ```shell
   docker cp analyze.py CONTAINERID:/home/
   docker cp WIN_sample CONTAINERID:/tmp/sample
   ```

   - A终端：运行分析脚本，查看结果/tmp/result

   ```shell
   python /home/analyze.py -f /tmp/sample -m win
   ...
   ll /tmp/result
   ```

   ​在结果wine.txt中，查找 /home/sample.exe 看看是否正常运行成功。​



1. container.py