# nmap_to_csv
将Nmap扫描生成的XML结果文件转换为CSV格式，并支持获取ip端口的http信息。

# 使用举例
```shell
python3 nmap_to_csv.py 1.xml 2.xml
python3 nmap_to_csv.py 1.xml 2.xml -r
python3 nmap_to_csv.py 1.xml 2.xml -r -t 100
```
# 结果csv文件
![csv.png](csv.png)
# 参数
```shell
usage: nmap_to_csv.py [-h] [-r] [-t T] nmap_xml_files [nmap_xml_files ...]

positional arguments:
  nmap_xml_files   Nmap使用-oX参数输出的XML文件，多个文件空格隔开。    
                   推荐nmap参数：nmap -sS -P0 -n -v -p1-65535 192.168.1.1 -T4 --min-rate=2000 -oX result.xml    
                   （-sV识别版本较慢，全端口扫描不建议加）

optional arguments:
  -h, --help       show this help message and exit
  -r, --req-title  请求Http获取Title和状态码
  -t T             Http请并发线程数（默认20)
```

# 更新日志
```
2025/3/28,支持获取title、响应码
2021/12/30,支持从内存中读取xml
2021/12/18,字段优化
```
