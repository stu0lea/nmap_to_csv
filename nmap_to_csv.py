#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
@author: stu0lea
@file: nmap_to_csv.py
@version: 3.0
@update: 2025/03/28
"""
import xml.etree.ElementTree as ET
import sys
import csv
import argparse
from collections import defaultdict
import requests
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from requests.exceptions import RequestException
import logging
from tqdm import tqdm

requests.packages.urllib3.disable_warnings()


class NmapToCSVConverter:
    """Nmap XML结果转CSV转换器"""

    CSV_HEADERS = [
        "主机名", "IP", "端口", "状态", "协议", "服务",
        "产品", "版本", "其他信息", "URL", "标题", "响应码"
    ]

    def __init__(self, req_title=False, max_workers=50, output_filename='result.csv'):
        self.req_title = req_title
        self.max_workers = max_workers
        self.output_filename = output_filename
        self.result = []
        self.file_stats = defaultdict(dict)  # 新增：存储各文件统计信息
        self.logger = self._configure_logger()

    def _configure_logger(self):
        """配置日志系统"""
        logger = logging.getLogger(self.__class__.__name__)
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s %(filename)s:%(lineno)d:%(funcName)s [%(levelname)s] %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    @staticmethod
    def _parse_title(text):
        """从HTML提取<title>标签"""
        try:
            start = text.find('<title>')
            if start == -1:
                return ''
            end = text.find('</title>', start)
            return text[start + 7:end] if end != -1 else text[start + 7:]
        except Exception:
            return ''

    def _get_http_info(self, ip, port):
        """获取HTTP服务信息"""
        urls = [f"https://{ip}:{port}", f"http://{ip}:{port}"]
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        for url in urls:
            try:
                self.logger.debug(f"请求URL: {url}")
                response = requests.get(
                    url, headers=headers, timeout=5,
                    verify=False, allow_redirects=True
                )
                response.encoding = response.apparent_encoding  # 自动检测编码防止编码错误
                return (
                    url,
                    self._parse_title(response.text).strip(),
                    str(response.status_code))
            except RequestException:
                continue
        return '', '', ''

    def parse_nmap(self, in_file):
        """解析Nmap XML文件"""
        # 获取实际文件名
        if isinstance(in_file, str):
            filename = in_file
        else:
            filename = getattr(in_file, 'name', '未知文件')

        self.logger.info(f"解析文件:{filename}")
        current_result = []

        try:
            root = ET.parse(in_file).getroot() if not hasattr(in_file, 'read') \
                else ET.fromstring(in_file.getvalue())
            hosts = list(root.iter('host'))
            total_hosts = len(hosts)
        except ET.ParseError as e:
            self.logger.error(f"XML解析失败:{str(e)}")
            sys.exit(1)

        with tqdm(total=total_hosts, desc=f"解析进度[{filename}]", unit="host") as pbar:
            ip_set = set()
            open_ports = 0

            for host in hosts:
                host_dict = dict.fromkeys(self.CSV_HEADERS, '')
                try:
                    status = host.find('status')
                    if status is None or status.get('state') == 'down':
                        pbar.update(1)
                        continue

                    ip = host.find('address').get('addr')
                    hostname_elem = host.find('hostnames/hostname')
                    host_dict.update({
                        "主机名": hostname_elem.get('name') if hostname_elem else ip,
                        "IP": ip
                    })

                    # 统计独立IP
                    if ip not in ip_set:
                        ip_set.add(ip)

                    ports = host.find('ports')
                    if ports is None or not ports.findall('port'):
                        current_result.append(host_dict)
                        pbar.update(1)
                        continue

                    for port in ports.iter('port'):
                        port_dict = host_dict.copy()
                        port_dict["端口"] = port.get('portid', '')
                        state = port.find('state')
                        port_status = state.get('state') if state is not None else ''
                        port_dict["状态"] = port_status

                        # 统计开放端口
                        if port_status == 'open':
                            open_ports += 1

                        port_dict["协议"] = port.get('protocol', '')
                        service = port.find('service')
                        if service is not None:
                            port_dict.update({
                                "服务": service.get('name', ''),
                                "产品": service.get('product', ''),
                                "版本": service.get('version', ''),
                                "其他信息": service.get('extrainfo', '')
                            })
                        current_result.append(port_dict)
                except Exception as e:
                    self.logger.error(f"解析失败: {str(e)}")
                pbar.update(1)

            # 记录单文件统计信息
            self.file_stats[filename] = {
                'ip_count': len(ip_set),
                'open_ports': open_ports
            }
        self.result.extend(current_result)
        return self.result

    def _count_open_ports(self):
        """统计开放端口"""
        counter = defaultdict(int)
        for entry in self.result:
            if entry.get('状态') == 'open':
                counter[entry['IP']] += 1
        return counter

    def process_http_requests(self):
        """处理HTTP请求"""
        if not self.req_title:
            return set(self.result)

        counter = self._count_open_ports()
        over_limit_ips = [ip for ip, count in counter.items() if count >= 1000]

        targets = [
            (idx, entry['IP'], entry['端口'])
            for idx, entry in enumerate(self.result)
            if (
                    entry.get('状态') == 'open' and
                    entry.get('协议') == 'tcp' and
                    entry['端口'].isdigit() and
                    entry['IP'] not in over_limit_ips
            )
        ]
        self.logger.info(f"启动HTTP请求处理（{len(targets)}个HTTP请求，线程数: {self.max_workers}）")
        with tqdm(total=len(targets), desc="HTTP请求", unit="req") as pbar:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for idx, ip, port in targets:
                    futures.append(executor.submit(
                        self._get_http_info, ip, port
                    ))

                for future, (idx, _, _) in zip(futures, targets):
                    try:
                        url, title, status = future.result()
                        self.result[idx].update({
                            "URL": url,
                            "标题": title,
                            "响应码": status
                        })
                    except Exception as e:
                        self.logger.error(f"请求异常: {str(e)}")
                    pbar.update(1)
        return self.result

    def write_csv(self, csv_http_io=False):
        """写入CSV文件"""
        if not self.result:
            self.logger.error("无数据可写入")
            return
        try:
            if not csv_http_io:
                # 写文件
                with open(self.output_filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=self.CSV_HEADERS)
                    writer.writeheader()
                    writer.writerows(self.result)
            else:
                # 返回给浏览器
                csv_http_io = StringIO()
                writer = csv.DictWriter(csv_io, fieldnames=self.CSV_HEADERS)
                writer.writeheader()
                writer.writerows(self.result)
                return csv_http_io
            self.logger.info(f"文件已保存:{self.output_filename}")
        except IOError as e:
            self.logger.error(f"写入失败:{str(e)}")

    def print_statistics(self):
        """打印统计信息"""
        # 各文件统计
        for filename, stats in self.file_stats.items():
            self.logger.info(
                f"各文件统计({filename}):IP数量={stats['ip_count']},开放端口={stats['open_ports']}"
            )

        # 总体统计
        total_ips = sum(stats['ip_count'] for stats in self.file_stats.values())
        total_ports = sum(stats['open_ports'] for stats in self.file_stats.values())
        stats_msg = [
            f"总体统计IP总数:{total_ips},开放端口总数:{total_ports}"
        ]
        if self.req_title:
            web_count = sum(1 for e in self.result if e.get('响应码'))
            stats_msg.append(f"Web服务:{web_count}")
        self.logger.info(",".join(stats_msg))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""Nmap生成的XML转CSV工具
推荐扫描参数：nmap -sS -Pn -n -v -p1-65535 目标IP -T4 --min-rate=2000 --host-timeout=5m -oX result.xml""",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-r', '--req-title', action='store_true',
                        help='获取HTTP标题和状态码')
    parser.add_argument('-t', type=int, default=50,
                        help='并发线程数（默认20）')
    parser.add_argument('-o', '--output', default='result.csv',
                        help='指定输出CSV文件名（默认：result.csv）')
    parser.add_argument('nmap_xml_files', nargs='+',
                        help="""XML文件列表，多个文件空格隔开""")
    args = parser.parse_args()
    converter = NmapToCSVConverter(
        req_title=args.req_title,
        max_workers=args.t,
        output_filename=args.output
    )
    for xml_file in args.nmap_xml_files:
        converter.parse_nmap(xml_file)
    if args.req_title:
        converter.process_http_requests()
    converter.write_csv()
    converter.print_statistics()
