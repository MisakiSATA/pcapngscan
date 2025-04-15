# PCAPNG流量分析工具

这是一个用于分析PCAPNG网络流量包的工具，使用Python开发。该工具完全基于Python实现，不需要依赖Wireshark。

## 功能特点

### 基础分析
- 基本信息分析（文件大小、数据包数量、时间范围等）
- 协议分布统计
- 流量大小分析

### 高级分析
- IP地址统计（源IP和目的IP分布）
- 端口使用情况分析
- 异常流量检测
  - 大包检测
  - 频繁通信IP检测
  - 异常端口检测
- 文件提取功能（从HTTP流量中提取文件）

### 可视化功能
- 流量时间序列图
- 源/目的IP分布图
- 端口使用情况图

### 导出功能
- 导出完整分析报告（JSON格式）
- 导出统计图表（PNG格式）

## 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

### 命令行模式

1. 基本用法：
```bash
python main.py your_file.pcapng
```

2. 指定输出目录：
```bash
python main.py your_file.pcapng --output custom_output_dir
```

3. 使用交互式菜单：
```bash
python main.py your_file.pcapng --interactive
```

### 交互式菜单说明

在交互式模式下，你可以通过菜单选择以下功能：

1. 显示基本信息
2. 显示协议分布
3. 显示IP分析
4. 显示端口分析
5. 显示异常检测
6. 显示提取的文件
7. 生成分析报告
8. 退出

## 输出说明

分析完成后，将在指定目录下生成以下文件：
- `analysis_report.json`: 包含所有分析结果的JSON文件
- `traffic_timeline.png`: 流量时间序列图
- `ip_distribution.png`: IP分布图
- `port_usage.png`: 端口使用情况图

## 依赖说明

- scapy: PCAPNG文件解析和网络数据包处理
- pandas: 数据处理
- matplotlib: 数据可视化
- numpy: 数值计算
- rich: 终端美化输出
- tqdm: 进度条显示

## 注意事项

- 对于大型PCAPNG文件，分析可能需要较长时间
- 文件提取功能目前仅支持HTTP协议
- 异常检测的阈值可以根据需要调整
- 交互式模式下，可以使用方向键和回车键进行选择
