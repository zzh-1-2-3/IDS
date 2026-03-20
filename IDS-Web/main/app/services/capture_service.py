import os
import time
import threading
import pandas as pd
import numpy as np
from datetime import datetime
from typing import List, Dict, Optional, Callable
from collections import defaultdict
import warnings
import platform
import socket
warnings.filterwarnings("ignore")

# 导入日志模块
from app.core.logger import log_capture

# 导入scapy
from scapy.all import sniff, IP, TCP, UDP, get_if_list, get_if_addr

# 尝试导入psutil
try:
    import psutil
    has_psutil = True
except ImportError:
    has_psutil = False
    log_capture("警告: 未安装psutil库，使用基础网卡检测")

class Flow:
    """流量流类"""
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, start_time):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.forward_packets = []
        self.backward_packets = []
        self.start_time = start_time
        self.last_seen = start_time
        
        self.fwd_packet_count = 0
        self.bwd_packet_count = 0
        self.fwd_byte_count = 0
        self.bwd_byte_count = 0
        self.fwd_total_len = 0
        self.bwd_total_len = 0
        self.fwd_header_len = 0
        self.bwd_header_len = 0
        self.fwd_iat_total = 0
        self.bwd_iat_total = 0
        self.active_time = 0
        self.idle_time = 0
        self.is_complete = False
    
    def add_packet(self, packet, direction, packet_time):
        current_time = packet_time
        packet_len = len(packet)
        
        # 计算空闲时间（当前数据包与前一个数据包的时间间隔）
        if self.fwd_packet_count + self.bwd_packet_count > 0:
            # 获取最后一个数据包的时间
            if self.forward_packets and self.backward_packets:
                last_packet_time = max(self.forward_packets[-1]['time'], self.backward_packets[-1]['time'])
            elif self.forward_packets:
                last_packet_time = self.forward_packets[-1]['time']
            else:
                last_packet_time = self.backward_packets[-1]['time']
            
            idle_time = current_time - last_packet_time
            if idle_time > 0:
                self.idle_time += idle_time
        
        if direction == 'forward':
            if self.fwd_packet_count > 0:
                self.fwd_iat_total += current_time - self.forward_packets[-1]['time']
            
            self.fwd_packet_count += 1
            self.fwd_byte_count += packet_len
            self.fwd_total_len += packet_len
            
            header_len = 20
            if packet.haslayer(TCP):
                header_len += 20
            elif packet.haslayer(UDP):
                header_len += 8
            
            self.fwd_header_len += header_len
            self.forward_packets.append({'time': current_time, 'size': packet_len, 'header_len': header_len})
            
        elif direction == 'backward':
            if self.bwd_packet_count > 0:
                self.bwd_iat_total += current_time - self.backward_packets[-1]['time']
            
            self.bwd_packet_count += 1
            self.bwd_byte_count += packet_len
            self.bwd_total_len += packet_len
            
            header_len = 20
            if packet.haslayer(TCP):
                header_len += 20
            elif packet.haslayer(UDP):
                header_len += 8
            
            self.bwd_header_len += header_len
            self.backward_packets.append({'time': current_time, 'size': packet_len, 'header_len': header_len})
        
        self.flow_duration = current_time - self.start_time
        self.last_seen = current_time
        
        # 流量完成条件：持续时间超过3秒或数据包数量超过3个
        if self.flow_duration > 3 or (self.fwd_packet_count + self.bwd_packet_count) >= 3:
            self.is_complete = True
    
    def is_expired(self, current_time=None):
        if current_time is None:
            current_time = time.time()
        return (current_time - self.last_seen) > 120
    
    def extract_features(self):
        """提取26个特征值（与CICIDS2017数据集一致）"""
        if self.fwd_packet_count == 0 and self.bwd_packet_count == 0:
            return None
        
        all_packets = self.forward_packets + self.backward_packets
        all_sizes = [p['size'] for p in all_packets]
        
        features = {
            'Flow Duration': self.flow_duration * 1000,
            'Total Fwd Packets': self.fwd_packet_count,
            'Total Backward Packets': self.bwd_packet_count,
            'Total Length of Fwd Packets': self.fwd_total_len,
            'Total Length of Bwd Packets': self.bwd_total_len,
            'Fwd Packet Length Max': max([p['size'] for p in self.forward_packets]) if self.forward_packets else 0,
            'Fwd Packet Length Min': min([p['size'] for p in self.forward_packets]) if self.forward_packets else 0,
            'Fwd Packet Length Mean': self.fwd_total_len / self.fwd_packet_count if self.fwd_packet_count > 0 else 0,
            'Bwd Packet Length Max': max([p['size'] for p in self.backward_packets]) if self.backward_packets else 0,
            'Bwd Packet Length Min': min([p['size'] for p in self.backward_packets]) if self.backward_packets else 0,
            'Bwd Packet Length Mean': self.bwd_total_len / self.bwd_packet_count if self.bwd_packet_count > 0 else 0,
            'Flow Bytes/s': (self.fwd_total_len + self.bwd_total_len) / self.flow_duration if self.flow_duration > 0 else 0,
            'Flow Packets/s': (self.fwd_packet_count + self.bwd_packet_count) / self.flow_duration if self.flow_duration > 0 else 0,
            'Fwd Header Length': self.fwd_header_len,
            'Bwd Header Length': self.bwd_header_len,
            'Fwd Packets/s': self.fwd_packet_count / self.flow_duration if self.flow_duration > 0 else 0,
            'Bwd Packets/s': self.bwd_packet_count / self.flow_duration if self.flow_duration > 0 else 0,
            'Min Packet Length': min(all_sizes) if all_sizes else 0,
            'Max Packet Length': max(all_sizes) if all_sizes else 0,
            'Packet Length Mean': (self.fwd_total_len + self.bwd_total_len) / (self.fwd_packet_count + self.bwd_packet_count) if (self.fwd_packet_count + self.bwd_packet_count) > 0 else 0,
            'Packet Length Std': np.std(all_sizes) if all_sizes else 0,
            'Packet Length Variance': np.var(all_sizes) if all_sizes else 0,
            'Fwd IAT Mean': self.fwd_iat_total / (self.fwd_packet_count - 1) if self.fwd_packet_count > 1 else 0,
            'Bwd IAT Mean': self.bwd_iat_total / (self.bwd_packet_count - 1) if self.bwd_packet_count > 1 else 0,
            'Active Mean': self.active_time / (self.fwd_packet_count + self.bwd_packet_count) if (self.fwd_packet_count + self.bwd_packet_count) > 0 else 0,
            'Idle Mean': self.idle_time / (self.fwd_packet_count + self.bwd_packet_count) if (self.fwd_packet_count + self.bwd_packet_count) > 0 else 0
        }
        
        return features
    
    def get_flow_info(self):
        return {
            'timestamp': datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'packet_size': self.fwd_total_len + self.bwd_total_len
        }


class FlowManager:
    """流量管理器"""
    def __init__(self):
        self.flows = {}
        self.completed_flows = []
        self.lock = threading.Lock()
    
    def process_packet(self, packet):
        with self.lock:
            if not packet.haslayer(IP):
                return None
            
            ip_packet = packet[IP]
            src_ip = ip_packet.src
            dst_ip = ip_packet.dst
            
            if ip_packet.haslayer(TCP):
                protocol = 'TCP'
                src_port = ip_packet[TCP].sport
                dst_port = ip_packet[TCP].dport
            elif ip_packet.haslayer(UDP):
                protocol = 'UDP'
                src_port = ip_packet[UDP].sport
                dst_port = ip_packet[UDP].dport
            else:
                return None
            
            # 使用数据包的时间戳
            packet_time = packet.time
            
            forward_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            backward_key = (dst_ip, src_ip, dst_port, src_port, protocol)
            
            if forward_key in self.flows:
                self.flows[forward_key].add_packet(packet, 'forward', packet_time)
                flow = self.flows[forward_key]
            elif backward_key in self.flows:
                self.flows[backward_key].add_packet(packet, 'backward', packet_time)
                flow = self.flows[backward_key]
            else:
                flow = Flow(src_ip, dst_ip, src_port, dst_port, protocol, packet_time)
                flow.add_packet(packet, 'forward', packet_time)
                self.flows[forward_key] = flow
            
            if flow.is_complete:
                self.completed_flows.append(flow)
                if forward_key in self.flows:
                    del self.flows[forward_key]
                elif backward_key in self.flows:
                    del self.flows[backward_key]
            
            return flow.get_flow_info()
    
    def clean_expired_flows(self):
        with self.lock:
            current_time = time.time()
            expired_keys = []
            
            for key, flow in self.flows.items():
                if flow.is_expired(current_time):
                    self.completed_flows.append(flow)
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.flows[key]
    
    def get_all_flows(self):
        with self.lock:
            return list(self.flows.values()) + self.completed_flows
    
    def clear_completed_flows(self):
        with self.lock:
            self.completed_flows = []


class CaptureService:
    """流量捕获服务"""
    _instance = None
    _is_capturing = False
    _capture_thread = None
    _flow_manager = None
    _packet_count = 0
    _callback = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CaptureService, cls).__new__(cls)
            cls._flow_manager = FlowManager()
        return cls._instance
    
    @staticmethod
    def get_network_interfaces():
        """获取可用网卡列表"""
        interfaces = []
        
        if has_psutil:
            # 使用psutil获取详细网卡信息
            try:
                addrs = psutil.net_if_addrs()
                stats = psutil.net_if_stats()
                
                for interface_name in addrs:
                    interface_info = {
                        "name": interface_name,
                        "ip": None,
                        "netmask": None,
                        "status": "unknown",
                        "is_up": False,
                        "is_loopback": False
                    }

                    # 检查接口状态
                    if interface_name in stats:
                        interface_info["is_up"] = stats[interface_name].isup
                        interface_info["status"] = "UP" if stats[interface_name].isup else "DOWN"

                    # 提取IPv4地址
                    for addr in addrs[interface_name]:
                        if addr.family == socket.AF_INET:
                            interface_info["ip"] = addr.address
                            interface_info["netmask"] = addr.netmask
                            if addr.address.startswith("127."):
                                interface_info["is_loopback"] = True
                            break

                    # 只添加启用且非回环的网卡
                    if interface_info["is_up"] and not interface_info["is_loopback"]:
                        display_ip = interface_info["ip"] or "无IP"
                        interfaces.append({
                            'name': interface_name,
                            'ip': interface_info["ip"] or "无IP",
                            'display': f"{interface_name} ({display_ip})"
                        })
            except Exception as e:
                log_capture(f"使用psutil获取网卡列表失败: {e}")
                # 回退到基础方法
                pass
        
        # 如果使用psutil失败或没有psutil，使用基础方法
        if not interfaces:
            try:
                iface_list = get_if_list()
                for iface in iface_list:
                    try:
                        ip = get_if_addr(iface)
                        if not ip or ip == '0.0.0.0':
                            ip = '无IP'
                        interfaces.append({
                            'name': iface,
                            'ip': ip,
                            'display': f"{iface} ({ip})"
                        })
                    except Exception as e:
                        # 即使获取IP失败，也添加网卡
                        interfaces.append({
                            'name': iface,
                            'ip': '获取失败',
                            'display': f"{iface} (获取失败)"
                        })
            except Exception as e:
                log_capture(f"获取网卡列表失败: {e}")
        
        # 始终添加"any"选项
        interfaces.append({
            'name': 'any',
            'ip': '所有网卡',
            'display': '所有网卡 (any)'
        })
        
        return interfaces
    
    def start_capture(self, interfaces: List[str], duration: int = 60, 
                     update_interval: int = 10, callback: Callable = None):
        """开始捕获流量"""
        if self._is_capturing:
            return False
        
        self._is_capturing = True
        self._packet_count = 0
        self._callback = callback
        self._flow_manager = FlowManager()
        self._sniff_instance = None
        self._update_interval = update_interval
        
        def capture_worker():
            try:
                # 处理interfaces参数
                if not interfaces or len(interfaces) == 0:
                    iface = None  # 使用默认网卡
                elif 'any' in interfaces:
                    iface = None  # any表示使用所有网卡
                else:
                    iface = interfaces[0]  # 只使用第一个网卡（scapy不支持多网卡同时捕获）
                
                def packet_handler(packet):
                    if not self._is_capturing:
                        log_capture("捕获已停止，退出处理")
                        return False
                    
                    try:
                        flow_info = self._flow_manager.process_packet(packet)
                        self._packet_count += 1
                        
                        if flow_info and self._callback:
                            self._callback(flow_info)
                        
                        return None  # 不返回True，避免scapy打印
                    except Exception as e:
                        log_capture(f"处理数据包时出错: {e}")
                        return None  # 不返回True，避免scapy打印
                
                # 启动清理线程
                def clean_worker():
                    while self._is_capturing:
                        time.sleep(10)
                        self._flow_manager.clean_expired_flows()
                
                clean_thread = threading.Thread(target=clean_worker)
                clean_thread.daemon = True
                clean_thread.start()
                
                # 启动定期处理线程
                def process_worker():
                    while self._is_capturing:
                        time.sleep(self._update_interval)
                        if self._is_capturing:
                            # 处理已完成的流量
                            completed_flows = self._flow_manager.completed_flows.copy()
                            if completed_flows and self._callback:
                                # 这里可以添加批量处理逻辑
                                log_capture(f"定期处理 {len(completed_flows)} 个已完成的流量")
                                # 清空已处理的流量
                                self._flow_manager.clear_completed_flows()
                
                process_thread = threading.Thread(target=process_worker)
                process_thread.daemon = True
                process_thread.start()
                
                # 开始捕获
                log_capture(f"开始捕获流量，网卡: {iface or '所有网卡'}")
                log_capture(f"更新间隔: {self._update_interval}秒")
                # 使用timeout参数，确保能定期检查捕获状态
                start_time = time.time()
                while self._is_capturing and (time.time() - start_time) < duration:
                    # 每次捕获1秒
                    sniff(iface=iface, prn=packet_handler, store=False, timeout=1)
                
            except Exception as e:
                log_capture(f"捕获过程中发生错误: {e}")
            finally:
                self._is_capturing = False
                self._capture_thread = None
                log_capture("捕获已停止")
        
        self._capture_thread = threading.Thread(target=capture_worker)
        self._capture_thread.daemon = True
        self._capture_thread.start()
        
        return True
    
    def stop_capture(self):
        """停止捕获"""
        log_capture("尝试停止捕获...")
        self._is_capturing = False
        thread = self._capture_thread
        if thread and thread.is_alive():
            log_capture(f"等待捕获线程结束...")
            thread.join(timeout=5)  # 增加超时时间
            if thread.is_alive():
                log_capture("捕获线程仍在运行，强制结束")
        log_capture("捕获已停止")
        # 重置状态
        self._capture_thread = None
        return self._flow_manager.get_all_flows()
    
    def is_capturing(self):
        return self._is_capturing
    
    def get_flows(self):
        return self._flow_manager.get_all_flows()
    
    def get_flow_count(self):
        all_flows = self._flow_manager.get_all_flows()
        return len(all_flows)
    
    def get_packet_count(self):
        return self._packet_count


# 全局捕获服务实例
capture_service = CaptureService()
