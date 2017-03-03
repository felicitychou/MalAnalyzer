# MalAnalyzer

Based Docker Wine Strace Python2.7

1. Install docker

2. pull lmas & wmas docker images
   ```docker pull felicitychou/lmas```
   ```docker pull felicitychou/wmas```

3. Install docker
   ```pip install docker```


功能点
- 获取文件基本信息
   - 文件名、文件大小、hash值、文件类型、ssdeep
   - 壳信息／脱壳 upx、PE文件信息、strings （计划）

- 静态分析
   - yara检测、
   - clamav库（计划）
- 动态分析
   - 动态数据获取：tcpdump、strace／ltrace（ELF）、Wine（EXE）（测试中）
   - 数据解析 （计划）


框架

- MalAnalyzer.py 主模块
- static_analyze.py 静态分析
- dynamic_analyze.py 动态分析
- container.py 容器调度
- container_code/analyze.py 容器里运行样本脚本
- conf.py 配置文件 
- log.py 日志模块



future
1. support python 3



---

Yara

https://github.com/VirusTotal/yara-python

pip install yara-python

