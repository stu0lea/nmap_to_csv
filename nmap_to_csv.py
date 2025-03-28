#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
@author: stu0lea
@file:nmap_to_csv.py
@time:2019/10/06
@version:2.0
"""
import xml.etree.ElementTree as ET
import sys
import csv
import argparse
from collections import defaultdict
import requests
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from requests import URLRequired
from requests.exceptions import RequestException
import logging
from tqdm import tqdm

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()

# 配置日志系统
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(pathname)s:%(lineno)d:%(funcName)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


def get_http_info(ip, port):
    """发送HTTP请求并获取标题和状态码"""
    urls = [f"https://{ip}:{port}", f"http://{ip}:{port}"]
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    for url in urls:
        try:
            logger.debug(f"正在请求URL: {url}")
            response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)
            status_code = str(response.status_code)
            title = parse_title(response.text).strip()
            return url, title, status_code
        except RequestException as e:
            logger.debug(f"HTTP请求失败: {url} [错误: {str(e)}]")
            continue
    return '', '', ''


def parse_title(text):
    """从HTML提取<title>标签（静默处理异常）"""
    try:
        start = text.find('<title>')
        if start == -1:
            return ''
        end = text.find('</title>', start)
        return text[start + 7:end] if end != -1 else text[start + 7:]
    except Exception as e:
        logger.debug(f"解析标题失败: {str(e)}")
        return ''


def parse_nmap(in_file):
    """解析xml文件"""
    logger.info(f"开始解析xml文件: {in_file}")
    try:
        root = ET.parse(in_file).getroot() if not hasattr(in_file, 'read') else ET.fromstring(in_file.getvalue())
        # 预解析统计主机总数
        total_hosts = sum(1 for _ in root.iter('host'))
    except ET.ParseError as e:
        logger.error(f"XML解析失败: {str(e)}")
        sys.exit(1)
    result = []
    ip_open_ports = defaultdict(int)  # 统计每个IP的开放端口数
    # 添加进度条：总主机数为进度条长度，动态显示IP
    with tqdm(total=total_hosts, desc="解析xml进度", unit="host") as pbar:
        for host in root.iter('host'):
            try:
                if host.find('status').get('state') == 'down':
                    pbar.update(1)
                    continue
                ip = host.find('address').get('addr')
                hostname_elem = host.find('hostnames/hostname')
                hostname = hostname_elem.get('name') if hostname_elem is not None else ip
                host_dict = {
                    "主机名": hostname, "IP": ip, "端口": '', "状态": '', "协议": '',
                    "服务": '', "产品": '', "版本": '', "其他信息": '', "URL":'', "标题": '', "响应码": ''
                }
                ports = host.find('ports')
                if ports is None or not ports.findall('port'):
                    result.append(host_dict)
                    pbar.update(1)
                    continue
                for port in ports.iter('port'):
                    port_dict = host_dict.copy()
                    port_dict["端口"] = port.get('portid', '')
                    state = port.find('state')
                    port_dict["状态"] = state.get('state') if state is not None else ''
                    port_dict["协议"] = port.get('protocol', '')
                    service = port.find('service')
                    if service is not None:
                        port_dict.update({
                            "服务": service.get('name', ''),
                            "产品": service.get('product', ''),
                            "版本": service.get('version', ''),
                            "其他信息": service.get('extrainfo', '')
                        })
                    result.append(port_dict)
                    # 统计每个IP开放端口数量
                    if port_dict["状态"] == 'open':
                        ip_open_ports[ip] += 1
            except Exception as e:
                logger.error(f"解析主机 {ip} 失败: {str(e)}")
            pbar.update(1)
    return result,ip_open_ports


def process_http_requests(result, ip_open_ports, max_workers=20):
    """多线程处理HTTP请求"""
    logger.info(f"开始请求HTTP")
    over_limit_ip_list = []
    for ip, count in ip_open_ports.items():
        if count >= 1000:
            over_limit_ip_list.append(ip)
            logger.warning(f"发现开放端口超过1000的IP：{ip}，开放端口数: {count}，跳过http请求！")

    targets = []
    for idx, entry in enumerate(result):
        if entry.get('状态') == 'open' and entry.get('协议') == 'tcp' and entry['端口'].isdigit():
            ip = entry['IP']
            if ip in over_limit_ip_list:
                continue
            else:
                targets.append((idx, ip, entry['端口']))

    logger.info(f"开始请求http（{len(targets)}个HTTP请求，线程数: {max_workers}）")
    # 进度条初始化
    http_pbar = tqdm(total=len(targets), desc="HTTP请求进度", unit="req")

    def update_entry(args):
        idx, ip, port = args
        url, title, status = get_http_info(ip, port)
        return idx, url, title, status

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(update_entry, target) for target in targets]
        for future in futures:
            try:
                idx, url, title, status = future.result()
                result[idx]['URL'] = url
                result[idx]['标题'] = title
                result[idx]['响应码'] = status
            except Exception as e:
                logger.error(f"线程处理异常: {str(e)}")
            http_pbar.update(1)  # 每个请求完成更新进度
    http_pbar.close()
    logger.info("所有HTTP请求处理完成")
    web_service_count = 0
    for entry in result:
        if entry.get('响应码', '').strip():
            web_service_count += 1
    return result, web_service_count

def write_csv(result, out_filename, result_is_io=False):
    """写入CSV文件"""
    try:
        if not result:
            logger.error("无数据可写入CSV文件")
            return
        if not result_is_io:
            with open(out_filename, 'w', newline='', encoding='utf-8', errors='ignore') as f:
                writer = csv.DictWriter(f, fieldnames=result[0].keys())
                writer.writeheader()
                writer.writerows(result)
        else:
            csv_io = StringIO()
            header = result[0].keys()  # 数据列名
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()  # 写入列名
            writer.writerows(result)  # 写入数据
            return csv_io
        logger.info(f"CSV文件已生成: {out_filename}")
    except IOError as e:
        logger.error(f"文件写入失败: {out_filename} [错误: {str(e)}]")


def print_statistics(result, ip_open_ports, req_title=False, web_service_count=0):
    """打印统计信息"""
    """通过logger单行输出统计信息"""
    stats = []

    # 基础统计
    total_ips = len(ip_open_ports)
    total_ports = sum(ip_open_ports.values())
    stats.append(f"IP数量：{total_ips}个")
    stats.append(f"开放端口：{total_ports}个")

    # Web服务统计（仅在启用 -r 时显示）
    if req_title:
        stats.append(f"Web服务：{web_service_count}个")

    # 单行日志输出
    logger.info(f"统计信息: {', '.join(stats)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='''Nmap XML转CSV工具
    ''',formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-r','--req-title', action='store_true', help='请求Http获取Title和状态码')
    parser.add_argument('-t', type=int, default=20, help='Http请并发线程数（默认20）')
    parser.add_argument('nmap_xml_files', nargs='+', help="""Nmap使用-oX参数输出的XML文件，多个文件空格隔开。\
    \n推荐nmap参数：nmap -sS -P0 -n -v -p1-65535 192.168.1.1 -T4 --min-rate=2000 -oX result.xml\
    \n（-sV识别版本较慢，全端口扫描不建议加）""")
    args = parser.parse_args()
    for nmap_xml_file in args.nmap_xml_files:
        result, ip_open_ports = parse_nmap(nmap_xml_file)
        web_service_count = 0  # 初始化

        if args.req_title:
            result, web_service_count = process_http_requests(result, ip_open_ports, max_workers=args.t)

        out_filename = nmap_xml_file.replace('.xml', '.csv')
        write_csv(result, out_filename)

        # 打印统计信息（每个文件单独统计）
        print_statistics(result, ip_open_ports, args.req_title, web_service_count)