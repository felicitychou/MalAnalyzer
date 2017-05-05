# MalAnalyzer

Based Docker Wine Strace Python2.7


## 功能点

- 获取文件基本信息
    - 文件名、文件类型、文件大小【完成】
    - hash值（md5、sha256、crc32）、ssdeep 【完成】
    - strings 【完成】
    - 壳信息（PE/ELF）【未完成，预计用yara检测】
    - PE/ELF信息 【未完成，需要测试和集成ELFParse】

- 静态分析
    - yara检测 【完成】
    - VT查询 【完成】
    - clamav检测 【未完成】
   
- 动态分析
    - 识别运行平台 【完成】
    - 动态数据获取：tcpdump、strace／ltrace（ELF）、Wine（EXE）【完成】
    - Wine数据解析 【未完成】
    - Strace数据解析 【未完成】
    - ltrace数据解析 【未完成】
    - tcpdump数据解析 【未完成】


## 框架

- MalAnalyzer.py 主模块
- core/static_analyze.py 静态分析
- core/dynamic_analyze.py 动态分析
- core/container.py 容器调度
- core/code/container_analyze.py 容器里运行样本脚本
- core/conf.py 配置文件 
- core/logger.py 日志模块
- core/output.py 报告输出模块



## future
1. support python 3


