import scapy.all as scapy
from scapy.layers import http
import pandas as pd
import numpy as np
from typing import List, Dict, Tuple
import matplotlib.pyplot as plt
from pathlib import Path
import json
from datetime import datetime
import os
from collections import defaultdict
import warnings
import argparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt, Confirm
import sys
from tqdm import tqdm
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor
import time
import re
import networkx as nx
from matplotlib.patches import FancyArrowPatch
import matplotlib.patches as mpatches
import magic  # 用于文件类型识别
import hashlib  # 用于文件哈希计算
import yara  # 用于恶意软件检测

warnings.filterwarnings('ignore')
console = Console()

# 敏感关键词列表
SENSITIVE_KEYWORDS = [
    'password', 'login', 'admin', 'root', 'user', 'pass', 'key', 'token',
    'secret', 'auth', 'credential', 'session', 'cookie', 'jwt', 'ssh',
    'private', 'certificate', 'database', 'config', 'backup'
]

# 常见攻击特征
ATTACK_PATTERNS = {
    'sql_injection': [r'select.*from', r'union.*select', r'insert.*into', r'delete.*from'],
    'xss': [r'<script>', r'javascript:', r'onerror=', r'onload='],
    'command_injection': [r'&&', r'||', r';', r'`', r'$\(', r'%0A'],
    'path_traversal': [r'\.\./', r'\.\.\\', r'%2e%2e%2f'],
    'brute_force': [r'login.*failed', r'authentication.*failed', r'wrong.*password'],
    'webshell': [r'eval\(', r'base64_decode\(', r'system\(', r'exec\(', r'shell_exec\('],
    'malware': [r'powershell.*-enc', r'certutil.*-decode', r'bitsadmin.*/transfer']
}

# 危险文件类型
DANGEROUS_FILE_TYPES = {
    'executable': ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs'],
    'script': ['.php', '.asp', '.jsp', '.py', '.sh', '.pl'],
    'document': ['.doc', '.docx', '.xls', '.xlsx', '.pdf'],
    'archive': ['.zip', '.rar', '.7z', '.tar', '.gz']
}

def process_packet_batch(packets):
    """处理数据包批次的辅助函数"""
    batch_data = []
    for packet in packets:
        try:
            packet_info = {
                'timestamp': datetime.fromtimestamp(float(packet.time)),
                'length': len(packet),
                'protocol': packet.name
            }
            
            if packet.haslayer(scapy.IP):
                packet_info.update({
                    'src_ip': packet[scapy.IP].src,
                    'dst_ip': packet[scapy.IP].dst
                })
            
            if packet.haslayer(scapy.TCP):
                packet_info.update({
                    'src_port': packet[scapy.TCP].sport,
                    'dst_port': packet[scapy.TCP].dport
                })
            elif packet.haslayer(scapy.UDP):
                packet_info.update({
                    'src_port': packet[scapy.UDP].sport,
                    'dst_port': packet[scapy.UDP].dport
                })
            
            # 提取HTTP请求信息
            if packet.haslayer(http.HTTPRequest):
                http_layer = packet[http.HTTPRequest]
                packet_info.update({
                    'http_method': http_layer.Method.decode(),
                    'http_path': http_layer.Path.decode(),
                    'http_host': http_layer.Host.decode() if hasattr(http_layer, 'Host') else None,
                    'http_user_agent': http_layer.User_Agent.decode() if hasattr(http_layer, 'User_Agent') else None
                })
            
            # 提取HTTP响应信息
            if packet.haslayer(http.HTTPResponse):
                http_layer = packet[http.HTTPResponse]
                packet_info.update({
                    'http_status': http_layer.Status_Code.decode(),
                    'http_content_type': http_layer.Content_Type.decode() if hasattr(http_layer, 'Content_Type') else None
                })
            
            batch_data.append(packet_info)
        except Exception:
            continue
    
    return batch_data

class SecurityAnalyzer:
    def __init__(self, packets_data: List[Dict]):
        self.packets_data = packets_data
        self.df = pd.DataFrame(packets_data)
        self.sensitive_flows = []
        self.attack_patterns = []
        self.port_scan_attempts = []
        self.suspicious_ips = set()
        
    def analyze_sensitive_protocols(self):
        """分析敏感协议"""
        sensitive_protocols = {
            'http': [],
            'ftp': [],
            'telnet': [],
            'smtp': [],
            'pop3': []
        }
        
        for packet in self.packets_data:
            if 'protocol' in packet:
                protocol = packet['protocol'].lower()
                if protocol in sensitive_protocols:
                    sensitive_protocols[protocol].append(packet)
        
        return sensitive_protocols
    
    def detect_port_scan(self):
        """检测端口扫描行为"""
        # 统计每个源IP访问的不同端口数量
        port_scan_stats = defaultdict(set)
        for packet in self.packets_data:
            if 'src_ip' in packet and 'dst_port' in packet:
                port_scan_stats[packet['src_ip']].add(packet['dst_port'])
        
        # 如果某个IP在短时间内访问了大量不同端口，可能是端口扫描
        suspicious_ips = []
        for ip, ports in port_scan_stats.items():
            if len(ports) > 50:  # 阈值可以根据实际情况调整
                suspicious_ips.append({
                    'ip': ip,
                    'ports_accessed': len(ports),
                    'ports': list(ports)
                })
                self.suspicious_ips.add(ip)
        
        return suspicious_ips
    
    def analyze_http_traffic(self):
        """分析HTTP流量中的敏感信息"""
        sensitive_http = []
        for packet in self.packets_data:
            if packet.get('protocol', '').lower() == 'http':
                # 检查URL和请求内容中的敏感关键词
                if any(keyword in str(packet).lower() for keyword in SENSITIVE_KEYWORDS):
                    sensitive_http.append(packet)
        
        return sensitive_http
    
    def detect_attack_patterns(self):
        """检测攻击特征"""
        detected_attacks = []
        for packet in self.packets_data:
            packet_str = str(packet).lower()
            for attack_type, patterns in ATTACK_PATTERNS.items():
                if any(re.search(pattern, packet_str) for pattern in patterns):
                    detected_attacks.append({
                        'attack_type': attack_type,
                        'packet': packet
                    })
        
        return detected_attacks
    
    def analyze_brute_force(self):
        """分析暴力破解尝试"""
        failed_auth_attempts = defaultdict(int)
        for packet in self.packets_data:
            packet_str = str(packet).lower()
            if any(pattern in packet_str for pattern in ATTACK_PATTERNS['brute_force']):
                if 'src_ip' in packet:
                    failed_auth_attempts[packet['src_ip']] += 1
        
        # 统计每个IP的失败认证次数
        suspicious_ips = []
        for ip, count in failed_auth_attempts.items():
            if count > 10:  # 阈值可以根据实际情况调整
                suspicious_ips.append({
                    'ip': ip,
                    'failed_attempts': count
                })
                self.suspicious_ips.add(ip)
        
        return suspicious_ips
    
    def generate_security_report(self) -> Dict:
        """生成安全分析报告"""
        report = {
            'sensitive_protocols': self.analyze_sensitive_protocols(),
            'port_scan_attempts': self.detect_port_scan(),
            'sensitive_http_traffic': self.analyze_http_traffic(),
            'detected_attacks': self.detect_attack_patterns(),
            'brute_force_attempts': self.analyze_brute_force(),
            'suspicious_ips': list(self.suspicious_ips)
        }
        
        # 分析攻击者意图
        attack_intentions = []
        
        # 端口扫描意图
        if report['port_scan_attempts']:
            attack_intentions.append({
                'type': '端口扫描',
                'description': '攻击者可能在寻找开放的服务和漏洞',
                'confidence': '高',
                'evidence': f"发现 {len(report['port_scan_attempts'])} 个IP进行了端口扫描"
            })
        
        # 暴力破解意图
        if report['brute_force_attempts']:
            attack_intentions.append({
                'type': '暴力破解',
                'description': '攻击者试图通过多次尝试获取系统访问权限',
                'confidence': '高',
                'evidence': f"发现 {len(report['brute_force_attempts'])} 个IP进行了暴力破解尝试"
            })
        
        # SQL注入意图
        sql_injections = [a for a in report['detected_attacks'] if a['attack_type'] == 'sql_injection']
        if sql_injections:
            attack_intentions.append({
                'type': 'SQL注入',
                'description': '攻击者试图通过SQL注入获取数据库信息',
                'confidence': '高',
                'evidence': f"发现 {len(sql_injections)} 次SQL注入尝试"
            })
        
        # XSS攻击意图
        xss_attacks = [a for a in report['detected_attacks'] if a['attack_type'] == 'xss']
        if xss_attacks:
            attack_intentions.append({
                'type': 'XSS攻击',
                'description': '攻击者试图通过XSS攻击获取用户会话信息',
                'confidence': '中',
                'evidence': f"发现 {len(xss_attacks)} 次XSS攻击尝试"
            })
        
        report['attack_intentions'] = attack_intentions
        return report

class NetworkTopology:
    def __init__(self, packets_data: List[Dict]):
        self.packets_data = packets_data
        self.graph = nx.DiGraph()
        self.connections = defaultdict(lambda: defaultdict(int))
        self.device_types = {}
        self._build_topology()
    
    def _identify_device_type(self, ip: str, ports: set) -> str:
        """识别设备类型"""
        # 常见服务端口
        common_ports = {
            'router': {80, 443, 22, 23, 179, 161},  # 路由器和交换机
            'server': {80, 443, 21, 22, 23, 25, 53, 3306, 5432, 3389},  # 服务器
            'client': {80, 443, 21, 22, 23, 25, 53, 3389},  # 客户端
            'printer': {515, 631, 9100},  # 打印机
            'camera': {554, 8554, 8000, 8080},  # 摄像头
            'database': {1433, 1521, 3306, 5432},  # 数据库
            'mail': {25, 110, 143, 465, 587, 993, 995},  # 邮件服务器
            'dns': {53, 853},  # DNS服务器
            'ftp': {20, 21},  # FTP服务器
            'ssh': {22},  # SSH服务器
            'telnet': {23},  # Telnet服务器
            'rdp': {3389}  # 远程桌面
        }
        
        # 统计端口匹配数
        matches = {dev_type: len(ports & common_ports[dev_type]) 
                  for dev_type in common_ports}
        
        # 返回匹配最多的设备类型
        if matches:
            return max(matches.items(), key=lambda x: x[1])[0]
        return 'unknown'
    
    def _build_topology(self):
        """构建网络拓扑"""
        # 统计每个IP的端口使用情况
        ip_ports = defaultdict(set)
        for packet in self.packets_data:
            if 'src_ip' in packet and 'dst_ip' in packet:
                src = packet['src_ip']
                dst = packet['dst_ip']
                if 'src_port' in packet:
                    ip_ports[src].add(packet['src_port'])
                if 'dst_port' in packet:
                    ip_ports[dst].add(packet['dst_port'])
                self.connections[src][dst] += 1
                self.graph.add_edge(src, dst, weight=self.connections[src][dst])
        
        # 识别设备类型
        for ip, ports in ip_ports.items():
            self.device_types[ip] = self._identify_device_type(ip, ports)
    
    def get_topology_info(self) -> Dict:
        """获取拓扑信息"""
        return {
            'nodes': list(self.graph.nodes()),
            'edges': list(self.graph.edges()),
            'connections': dict(self.connections),
            'device_types': dict(self.device_types)
        }
    
    def draw_topology(self, output_path: Path):
        """绘制网络拓扑图"""
        plt.figure(figsize=(20, 15))
        
        # 使用更优化的布局算法
        pos = nx.spring_layout(self.graph, 
                             k=5,  # 增加节点间距
                             iterations=200,  # 增加迭代次数
                             scale=2.0,  # 增加整体布局范围
                             seed=42)  # 固定随机种子以获得稳定布局
        
        # 定义设备类型颜色和图标
        device_colors = {
            'router': '#FFB6C1',  # 浅粉色
            'server': '#98FB98',  # 浅绿色
            'client': '#87CEEB',  # 天蓝色
            'printer': '#DDA0DD',  # 梅红色
            'camera': '#F0E68C',  # 卡其色
            'database': '#FFA07A',  # 浅橙色
            'mail': '#D8BFD8',  # 蓟色
            'dns': '#F0F8FF',  # 爱丽丝蓝
            'ftp': '#FFE4B5',  # 莫卡辛色
            'ssh': '#E6E6FA',  # 薰衣草色
            'telnet': '#F5DEB3',  # 小麦色
            'rdp': '#DDA0DD',  # 梅红色
            'unknown': '#D3D3D3'  # 浅灰色
        }
        
        # 计算节点大小（基于连接数）
        node_sizes = [len(self.graph.edges(node)) * 800 + 2000 
                     for node in self.graph.nodes()]
        
        # 绘制节点
        node_colors = [device_colors.get(self.device_types.get(node, 'unknown'), '#D3D3D3') 
                      for node in self.graph.nodes()]
        
        nx.draw_networkx_nodes(self.graph, pos, 
                             node_size=node_sizes,
                             node_color=node_colors,
                             alpha=0.7,
                             edgecolors='black',
                             linewidths=2)
        
        # 绘制边
        edge_weights = [self.graph[u][v]['weight'] for u, v in self.graph.edges()]
        max_weight = max(edge_weights) if edge_weights else 1
        edge_widths = [w/max_weight * 4 + 1 for w in edge_weights]  # 调整线宽
        
        # 使用曲线边，增加弧度并调整箭头位置
        nx.draw_networkx_edges(self.graph, pos, 
                             width=edge_widths,
                             edge_color='#666666',  # 深灰色
                             arrows=True,
                             arrowsize=15,
                             arrowstyle='->',  # 使用更简洁的箭头样式
                             connectionstyle='arc3,rad=0.3',  # 增加弧度
                             alpha=0.6,
                             node_size=node_sizes,  # 考虑节点大小
                             min_source_margin=15,  # 增加源节点边距
                             min_target_margin=15)  # 增加目标节点边距
        
        # 添加标签
        labels = {}
        for node in self.graph.nodes():
            device_type = self.device_types.get(node, 'unknown')
            labels[node] = f"{node}\n({device_type})"
        
        # 调整标签位置以避免重叠
        label_pos = {}
        for node, (x, y) in pos.items():
            # 根据节点位置微调标签位置
            if y > 0:
                label_pos[node] = (x, y + 0.05)
            else:
                label_pos[node] = (x, y - 0.05)
        
        nx.draw_networkx_labels(self.graph, label_pos, 
                              labels=labels,
                              font_size=10,
                              font_family='SimHei',
                              font_weight='bold',
                              bbox=dict(facecolor='white', 
                                      edgecolor='none', 
                                      alpha=0.7,
                                      boxstyle='round,pad=0.2'))
        
        # 添加图例
        legend_elements = [mpatches.Patch(color=color, label=dev_type)
                         for dev_type, color in device_colors.items()]
        plt.legend(handles=legend_elements, 
                  loc='upper right',
                  title='设备类型',
                  fontsize=10,
                  title_fontsize=12,
                  bbox_to_anchor=(1.15, 1))  # 调整图例位置
        
        # 添加网格背景
        plt.grid(True, linestyle='--', alpha=0.1)
        
        # 设置坐标轴范围
        x_values = [x for x, y in pos.values()]
        y_values = [y for x, y in pos.values()]
        plt.xlim(min(x_values) - 0.2, max(x_values) + 0.2)
        plt.ylim(min(y_values) - 0.2, max(y_values) + 0.2)
        
        plt.title('网络拓扑图', fontsize=16, pad=20)
        plt.axis('on')  # 显示坐标轴
        
        # 调整布局
        plt.tight_layout()
        
        # 保存图片
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()

class AttackFlow:
    def __init__(self, security_report: Dict):
        self.report = security_report
        self.flow_steps = []
        self._analyze_flow()
    
    def _analyze_flow(self):
        """分析攻击流程"""
        # 端口扫描阶段
        if self.report['port_scan_attempts']:
            self.flow_steps.append({
                'stage': '侦察',
                'description': '端口扫描',
                'details': [f"IP: {scan['ip']} 扫描了 {scan['ports_accessed']} 个端口" 
                          for scan in self.report['port_scan_attempts']]
            })
        
        # 暴力破解阶段
        if self.report['brute_force_attempts']:
            self.flow_steps.append({
                'stage': '入侵',
                'description': '暴力破解',
                'details': [f"IP: {attempt['ip']} 进行了 {attempt['failed_attempts']} 次尝试" 
                          for attempt in self.report['brute_force_attempts']]
            })
        
        # 攻击尝试阶段
        if self.report['detected_attacks']:
            attack_details = defaultdict(list)
            for attack in self.report['detected_attacks']:
                attack_details[attack['attack_type']].append(attack['packet'])
            
            self.flow_steps.append({
                'stage': '攻击',
                'description': '漏洞利用',
                'details': [f"{attack_type}: {len(packets)} 次尝试" 
                          for attack_type, packets in attack_details.items()]
            })
    
    def draw_flow(self, output_path: Path):
        """绘制攻击流程图"""
        plt.figure(figsize=(15, 8))
        
        # 定义阶段颜色
        colors = {
            '侦察': 'lightblue',
            '入侵': 'orange',
            '攻击': 'red'
        }
        
        # 绘制流程图
        for i, step in enumerate(self.flow_steps):
            # 绘制阶段框
            plt.gca().add_patch(mpatches.Rectangle(
                (i*5, 0), 4, 3, 
                facecolor=colors[step['stage']],
                alpha=0.3
            ))
            
            # 添加文本
            plt.text(i*5 + 2, 2.5, step['stage'], ha='center', va='center', fontsize=12)
            plt.text(i*5 + 2, 1.5, step['description'], ha='center', va='center', fontsize=10)
            
            # 添加详细信息
            for j, detail in enumerate(step['details']):
                plt.text(i*5 + 2, 1 - j*0.3, detail, ha='center', va='center', fontsize=8)
            
            # 绘制箭头
            if i < len(self.flow_steps) - 1:
                plt.arrow(i*5 + 4, 1.5, 1, 0, head_width=0.2, head_length=0.2, fc='k', ec='k')
        
        plt.xlim(-1, len(self.flow_steps)*5)
        plt.ylim(-1, 4)
        plt.axis('off')
        plt.title('攻击流程图', fontsize=16)
        
        # 保存图片
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

class FileAnalyzer:
    def __init__(self):
        self.mime = magic.Magic(mime=True)
        self.dangerous_files = []
        self.suspicious_files = []
    
    def analyze_file(self, data: bytes, filename: str) -> Dict:
        """分析文件内容"""
        result = {
            'filename': filename,
            'size': len(data),
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'mime_type': self.mime.from_buffer(data),
            'is_dangerous': False,
            'threats': []
        }
        
        # 检查文件类型
        file_ext = os.path.splitext(filename)[1].lower()
        for category, extensions in DANGEROUS_FILE_TYPES.items():
            if file_ext in extensions:
                result['is_dangerous'] = True
                result['threats'].append(f"危险文件类型: {category}")
        
        # 检查文件内容
        content = data.decode('utf-8', errors='ignore')
        for pattern_type, patterns in ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    result['is_dangerous'] = True
                    result['threats'].append(f"检测到{pattern_type}特征")
        
        # 检查敏感信息
        for keyword in SENSITIVE_KEYWORDS:
            if keyword in content.lower():
                result['is_dangerous'] = True
                result['threats'].append(f"包含敏感关键词: {keyword}")
        
        return result

class PCAPNGAnalyzer:
    def __init__(self, pcapng_file: str, filter_expression: str = None):
        """初始化分析器"""
        self.pcapng_file = pcapng_file
        self.filter_expression = filter_expression
        self.packets = []
        self.packets_data = []
        self.df = None
        self.security_analyzer = None
        self.network_topology = None
        self.attack_flow = None
        self.file_analyzer = FileAnalyzer()
        
        # 创建输出目录
        self.output_dir = Path("output")
        self.output_dir.mkdir(exist_ok=True)
        
        # 创建带时间戳的子目录
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.analysis_dir = self.output_dir / f"analysis_{timestamp}"
        self.analysis_dir.mkdir(exist_ok=True)
        
        self._load_capture()
    
    def _load_capture(self):
        """加载捕获文件"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("正在加载PCAPNG文件...", total=None)
            try:
                if not os.path.exists(self.pcapng_file):
                    raise FileNotFoundError(f"文件不存在: {self.pcapng_file}")
                
                # 使用scapy加载文件
                self.packets = scapy.rdpcap(self.pcapng_file)
                
                if self.filter_expression:
                    console.print(f"[yellow]应用过滤表达式: {self.filter_expression}[/yellow]")
                    self.packets = [p for p in self.packets if p.haslayer(scapy.IP) and 
                                  (p[scapy.IP].src == self.filter_expression or 
                                   p[scapy.IP].dst == self.filter_expression)]
                
                # 使用多进程处理数据包
                num_cores = mp.cpu_count()
                batch_size = max(1, len(self.packets) // (num_cores * 4))
                
                packet_batches = [self.packets[i:i + batch_size] 
                                for i in range(0, len(self.packets), batch_size)]
                
                with ProcessPoolExecutor(max_workers=num_cores) as executor:
                    results = list(tqdm(
                        executor.map(process_packet_batch, packet_batches),
                        total=len(packet_batches),
                        desc="处理数据包"
                    ))
                
                self.packets_data = [item for batch in results for item in batch]
                self.df = pd.DataFrame(self.packets_data)
                self.security_analyzer = SecurityAnalyzer(self.packets_data)
                self.network_topology = NetworkTopology(self.packets_data)
                
                progress.update(task, completed=True, description="文件加载完成！")
            except Exception as e:
                console.print(f"[red]错误: 无法加载文件 {self.pcapng_file}[/red]")
                console.print(f"[red]详细信息: {str(e)}[/red]")
                sys.exit(1)
    
    def analyze_files(self):
        """分析流量中的文件"""
        dangerous_files = []
        suspicious_files = []
        
        # 提取HTTP请求中的文件
        for packet in self.packets:
            if packet.haslayer(http.HTTPRequest):
                try:
                    http_layer = packet[http.HTTPRequest]
                    if hasattr(http_layer, 'Path'):
                        path = http_layer.Path.decode()
                        if any(path.endswith(ext) for exts in DANGEROUS_FILE_TYPES.values() for ext in exts):
                            # 提取文件内容
                            if packet.haslayer(scapy.Raw):
                                file_data = packet[scapy.Raw].load
                                analysis = self.file_analyzer.analyze_file(file_data, path)
                                if analysis['is_dangerous']:
                                    dangerous_files.append(analysis)
                                elif analysis['threats']:
                                    suspicious_files.append(analysis)
                except Exception:
                    continue
        
        return dangerous_files, suspicious_files
    
    def get_basic_info(self) -> Dict:
        """获取基本信息"""
        info = {
            "文件大小": f"{Path(self.pcapng_file).stat().st_size / 1024:.2f} KB",
            "数据包数量": len(self.packets),
            "开始时间": self.df['timestamp'].min(),
            "结束时间": self.df['timestamp'].max(),
            "总流量": f"{self.df['length'].sum() / 1024:.2f} KB",
            "平均包大小": f"{self.df['length'].mean():.2f} bytes",
            "最大包大小": f"{self.df['length'].max()} bytes",
            "最小包大小": f"{self.df['length'].min()} bytes"
        }
        return info
    
    def analyze_protocols(self) -> Dict[str, int]:
        """分析协议分布"""
        return self.df['protocol'].value_counts().to_dict()
    
    def analyze_ip_addresses(self) -> Tuple[Dict[str, int], Dict[str, int]]:
        """分析IP地址分布"""
        src_ips = self.df['src_ip'].value_counts().to_dict()
        dst_ips = self.df['dst_ip'].value_counts().to_dict()
        return src_ips, dst_ips
    
    def analyze_ports(self) -> Tuple[Dict[str, int], Dict[str, int]]:
        """分析端口使用情况"""
        src_ports = self.df['src_port'].value_counts().to_dict()
        dst_ports = self.df['dst_port'].value_counts().to_dict()
        return src_ports, dst_ports
    
    def detect_anomalies(self) -> Dict:
        """检测异常流量"""
        # 使用更高效的统计方法
        length_stats = self.df['length'].describe()
        mean = length_stats['mean']
        std = length_stats['std']
        
        anomalies = {
            'large_packets': self.df[self.df['length'] > mean + 3 * std],
            'frequent_ips': self.df['src_ip'].value_counts()[self.df['src_ip'].value_counts() > 1000].to_dict(),
            'unusual_ports': self.df['dst_port'].value_counts()[self.df['dst_port'].value_counts() < 5].to_dict()
        }
        return anomalies
    
    def extract_files(self) -> List[Dict]:
        """从流量中提取文件"""
        files = []
        # 只处理HTTP请求包
        http_packets = [p for p in self.packets if p.haslayer(http.HTTPRequest)]
        
        for packet in http_packets:
            try:
                http_layer = packet[http.HTTPRequest]
                file_info = {
                    'timestamp': datetime.fromtimestamp(float(packet.time)),
                    'source': packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'unknown',
                    'destination': packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'unknown',
                    'filename': http_layer.Path.decode() if hasattr(http_layer, 'Path') else 'unknown',
                    'content_type': http_layer.Content_Type.decode() if hasattr(http_layer, 'Content_Type') else 'unknown',
                    'size': len(packet)
                }
                files.append(file_info)
            except Exception:
                continue
        return files
    
    def plot_traffic_timeline(self):
        """绘制流量时间序列图"""
        plt.figure(figsize=(15, 6))
        self.df.set_index('timestamp')['length'].plot()
        plt.title('流量时间序列')
        plt.xlabel('时间')
        plt.ylabel('数据包大小 (bytes)')
        plt.tight_layout()
        plt.savefig(self.analysis_dir / 'traffic_timeline.png')
        plt.close()
    
    def plot_ip_distribution(self):
        """绘制IP分布图"""
        src_ips, dst_ips = self.analyze_ip_addresses()
        
        plt.figure(figsize=(15, 6))
        plt.subplot(1, 2, 1)
        pd.Series(src_ips).head(10).plot(kind='bar')
        plt.title('源IP分布 (Top 10)')
        plt.xticks(rotation=45)
        
        plt.subplot(1, 2, 2)
        pd.Series(dst_ips).head(10).plot(kind='bar')
        plt.title('目的IP分布 (Top 10)')
        plt.xticks(rotation=45)
        
        plt.tight_layout()
        plt.savefig(self.analysis_dir / 'ip_distribution.png')
        plt.close()
    
    def plot_port_usage(self):
        """绘制端口使用情况"""
        src_ports, dst_ports = self.analyze_ports()
        
        plt.figure(figsize=(15, 6))
        plt.subplot(1, 2, 1)
        pd.Series(src_ports).head(10).plot(kind='bar')
        plt.title('源端口使用情况 (Top 10)')
        plt.xticks(rotation=45)
        
        plt.subplot(1, 2, 2)
        pd.Series(dst_ports).head(10).plot(kind='bar')
        plt.title('目的端口使用情况 (Top 10)')
        plt.xticks(rotation=45)
        
        plt.tight_layout()
        plt.savefig(self.analysis_dir / 'port_usage.png')
        plt.close()
    
    def generate_comprehensive_report(self):
        """生成综合报告"""
        # 分析文件
        dangerous_files, suspicious_files = self.analyze_files()
        
        # 创建综合报告图
        plt.figure(figsize=(20, 15))
        plt.suptitle('PCAPNG流量分析报告', fontsize=16, y=0.95)
        
        # 1. 网络拓扑图
        plt.subplot(2, 2, 1)
        self.network_topology.draw_topology(self.analysis_dir / 'topology.png')
        plt.imshow(plt.imread(self.analysis_dir / 'topology.png'))
        plt.axis('off')
        plt.title('网络拓扑图', fontsize=12, pad=20)
        
        # 2. 流量时间序列
        plt.subplot(2, 2, 2)
        self.df.set_index('timestamp')['length'].plot(
            linewidth=1,
            color='blue',
            alpha=0.7
        )
        plt.title('流量时间序列', fontsize=12, pad=20)
        plt.xlabel('时间', fontsize=10)
        plt.ylabel('数据包大小 (bytes)', fontsize=10)
        plt.grid(True, linestyle='--', alpha=0.3)
        
        # 3. 协议分布
        plt.subplot(2, 2, 3)
        protocols = self.analyze_protocols()
        colors = plt.cm.Pastel1(np.linspace(0, 1, len(protocols)))
        plt.pie(protocols.values(), 
                labels=protocols.keys(),
                autopct='%1.1f%%',
                colors=colors,
                startangle=90,
                wedgeprops={'edgecolor': 'white', 'linewidth': 1})
        plt.title('协议分布', fontsize=12, pad=20)
        
        # 4. 攻击流程图
        plt.subplot(2, 2, 4)
        if self.security_analyzer:
            security_report = self.security_analyzer.generate_security_report()
            self.attack_flow = AttackFlow(security_report)
            self.attack_flow.draw_flow(self.analysis_dir / 'attack_flow.png')
            plt.imshow(plt.imread(self.analysis_dir / 'attack_flow.png'))
            plt.axis('off')
            plt.title('攻击流程图', fontsize=12, pad=20)
        
        # 调整布局
        plt.tight_layout(pad=3.0)
        
        # 保存图片
        plt.savefig(self.analysis_dir / 'comprehensive_report.png', 
                   dpi=300, 
                   bbox_inches='tight',
                   facecolor='white')
        plt.close()
        
        # 生成简化的文本报告
        with open(self.analysis_dir / 'summary.txt', 'w', encoding='utf-8') as f:
            f.write("流量分析摘要\n")
            f.write("=" * 50 + "\n\n")
            
            # 基本信息
            f.write("基本信息:\n")
            f.write("-" * 30 + "\n")
            basic_info = self.get_basic_info()
            for key, value in basic_info.items():
                f.write(f"{key}: {value}\n")
            
            # 安全分析
            if self.security_analyzer:
                security_report = self.security_analyzer.generate_security_report()
                f.write("\n安全分析:\n")
                f.write("-" * 30 + "\n")
                
                # 攻击意图
                if security_report['attack_intentions']:
                    f.write("检测到的攻击意图:\n")
                    for intention in security_report['attack_intentions']:
                        f.write(f"- {intention['type']}: {intention['description']}\n")
                        f.write(f"  可信度: {intention['confidence']}\n")
                
                # 可疑IP
                if security_report['suspicious_ips']:
                    f.write("\n可疑IP地址:\n")
                    for ip in security_report['suspicious_ips']:
                        f.write(f"- {ip}\n")
            
            # 文件分析
            if dangerous_files or suspicious_files:
                f.write("\n文件分析:\n")
                f.write("-" * 30 + "\n")
                
                if dangerous_files:
                    f.write("\n危险文件:\n")
                    for file in dangerous_files:
                        f.write(f"- 文件名: {file['filename']}\n")
                        f.write(f"  大小: {file['size']} bytes\n")
                        f.write(f"  MD5: {file['md5']}\n")
                        f.write(f"  威胁: {', '.join(file['threats'])}\n")
                
                if suspicious_files:
                    f.write("\n可疑文件:\n")
                    for file in suspicious_files:
                        f.write(f"- 文件名: {file['filename']}\n")
                        f.write(f"  大小: {file['size']} bytes\n")
                        f.write(f"  MD5: {file['md5']}\n")
                        f.write(f"  可疑特征: {', '.join(file['threats'])}\n")
            
            # 网络拓扑
            f.write("\n网络拓扑:\n")
            f.write("-" * 30 + "\n")
            topology_info = self.network_topology.get_topology_info()
            f.write(f"节点数量: {len(topology_info['nodes'])}\n")
            f.write(f"连接数量: {len(topology_info['edges'])}\n")
            f.write("\n主要连接:\n")
            for src, dsts in topology_info['connections'].items():
                for dst, count in dsts.items():
                    if count > 10:  # 只显示主要连接
                        f.write(f"- {src} -> {dst}: {count} 个数据包\n")

    def display_security_report(self):
        """显示安全分析报告"""
        if not self.security_analyzer:
            console.print("[red]错误: 安全分析器未初始化[/red]")
            return
        
        # 生成综合报告
        self.generate_comprehensive_report()
        
        # 显示摘要信息
        console.print("\n[bold cyan]分析摘要[/bold cyan]")
        console.print("=" * 50)
        
        # 基本信息
        basic_info = self.get_basic_info()
        table = Table(title="基本信息")
        table.add_column("项目", style="cyan")
        table.add_column("数值", style="magenta")
        for key, value in basic_info.items():
            table.add_row(key, str(value))
        console.print(table)
        
        # 安全分析
        security_report = self.security_analyzer.generate_security_report()
        if security_report['attack_intentions']:
            console.print("\n[bold red]检测到的攻击意图[/bold red]")
            for intention in security_report['attack_intentions']:
                console.print(f"- {intention['type']}: {intention['description']}")
                console.print(f"  可信度: {intention['confidence']}")
        
        # 可疑IP
        if security_report['suspicious_ips']:
            console.print("\n[bold red]可疑IP地址[/bold red]")
            for ip in security_report['suspicious_ips']:
                console.print(f"- {ip}")
        
        console.print(f"\n[green]详细报告已保存到 {self.analysis_dir}[/green]")
        console.print(f"[green]综合报告图: {self.analysis_dir / 'comprehensive_report.png'}[/green]")
        console.print(f"[green]分析摘要: {self.analysis_dir / 'summary.txt'}[/green]")

    def interactive_menu(self):
        """交互式菜单"""
        while True:
            console.print("\n[bold cyan]PCAPNG分析工具[/bold cyan]")
            console.print("1. 显示基本信息")
            console.print("2. 显示协议分布")
            console.print("3. 显示IP分析")
            console.print("4. 显示端口分析")
            console.print("5. 显示异常检测")
            console.print("6. 显示提取的文件")
            console.print("7. 显示安全分析报告")
            console.print("8. 生成分析报告")
            console.print("9. 退出")
            
            choice = Prompt.ask("请选择操作", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"])
            
            if choice == "1":
                self.display_basic_info()
            elif choice == "2":
                self.display_protocol_distribution()
            elif choice == "3":
                self.display_ip_analysis()
            elif choice == "4":
                self.display_port_analysis()
            elif choice == "5":
                self.display_anomalies()
            elif choice == "6":
                self.display_extracted_files()
            elif choice == "7":
                self.display_security_report()
            elif choice == "8":
                output_dir = Prompt.ask("请输入输出目录", default=None)
                self.generate_comprehensive_report()
                console.print(f"[green]分析报告已保存到 {self.analysis_dir} 目录[/green]")
            elif choice == "9":
                break

def main():
    parser = argparse.ArgumentParser(description='PCAPNG流量分析工具')
    parser.add_argument('file', help='PCAPNG文件路径')
    parser.add_argument('--output', '-o', help='输出目录', default=None)
    parser.add_argument('--interactive', '-i', action='store_true', help='使用交互式菜单')
    parser.add_argument('--filter', '-f', help='IP地址过滤，只分析指定IP的流量')
    parser.add_argument('--security', '-s', action='store_true', help='生成安全分析报告')
    args = parser.parse_args()
    
    start_time = time.time()
    analyzer = PCAPNGAnalyzer(args.file, args.filter)
    load_time = time.time() - start_time
    
    console.print(f"[green]文件加载完成，耗时: {load_time:.2f}秒[/green]")
    
    if args.security:
        analyzer.display_security_report()
    elif args.interactive:
        analyzer.interactive_menu()
    else:
        analyzer.generate_comprehensive_report()
        console.print(f"[green]分析报告已保存到 {analyzer.analysis_dir} 目录[/green]")

if __name__ == "__main__":
    main()
