# PCAPNG 流量分析与网络拓扑构建工具

本项目是一个基于 Python 的 PCAPNG 网络流量分析工具，专为无需 Wireshark 环境下的深度流量分析与可视化设计。**核心亮点在于：不仅能进行常规流量统计，还能自动根据流量包重建网络拓扑结构，直观展示主机间的通信关系。**

## 主要功能

### 1. 网络拓扑自动构建

- 根据捕获的流量包，自动识别网络中的主机、设备及其连接关系
- 生成交互式或静态的网络拓扑图，直观展示主机间的通信结构

### 2. 全面流量分析

- 基本信息统计（文件大小、数据包总数、时间范围等）
- 协议分布与流量大小分析
- 源/目的 IP 与端口分布统计

### 3. 异常与安全分析

- 大包、频繁通信 IP、异常端口等多维度异常检测
- 支持自定义阈值，灵活适配不同场景

### 4. 文件提取

- 自动从 HTTP 流量中提取文件，便于后续分析

### 5. 可视化与报告导出

- 生成流量时间序列图、IP 分布图、端口使用图、网络拓扑图等
- 支持导出 JSON 格式分析报告及 PNG 格式统计图表

## 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

### 命令行模式

- 基本用法：
  ```bash
  python main.py your_file.pcapng
  ```
- 指定输出目录：
  ```bash
  python main.py your_file.pcapng --output custom_output_dir
  ```
- 交互式菜单：
  ```bash
  python main.py your_file.pcapng --interactive
  ```

### 交互式菜单功能

1. 显示基本信息
2. 协议分布
3. IP 与端口分析
4. 异常检测
5. 文件提取
6. 网络拓扑图生成
7. 导出分析报告
8. 退出

## 输出内容

- `analysis_report.json`：完整分析结果
- `traffic_timeline.png`：流量时间序列图
- `ip_distribution.png`：IP 分布图
- `port_usage.png`：端口使用情况图
- `network_topology.png`：自动生成的网络拓扑图

## 依赖组件

- scapy：PCAPNG 解析与数据包处理
- pandas、numpy：数据处理与分析
- matplotlib：数据可视化
- networkx：网络拓扑建模与绘图
- rich、tqdm：终端美化与进度条

## 注意事项

- 大型 PCAPNG 文件分析耗时较长
- 文件提取目前仅支持 HTTP 协议
- 异常检测阈值可自定义
- 网络拓扑图可根据实际需求调整展示样式

---

**本工具适用于网络安全分析、流量溯源、教学演示等多种场景，助力用户高效理解和掌控网络通信全貌。**
