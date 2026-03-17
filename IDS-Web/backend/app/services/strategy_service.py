from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from datetime import datetime
from typing import List, Optional
import platform
import subprocess
import re

from app.models.strategy import ResponseStrategy, AdaptiveStrategy, ExecutedStrategy
from app.schemas.strategy import ResponseStrategyCreate, AdaptiveStrategyCreate
from app.core.logger import log_strategy

class StrategyService:
    @staticmethod
    def get_os_type():
        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "linux":
            return "linux"
        return "unknown"
    
    @staticmethod
    def generate_firewall_commands(strategy_type: str, direction: str, ip_range: str, 
                                   port_range: str = None, packet_limit: int = None):
        windows_commands = []
        linux_commands = []
        
        if strategy_type == "whitelist":
            # 白名单策略 - 允许特定IP，拒绝其他
            if ip_range:
                ips = [ip.strip() for ip in ip_range.split(",")]
                for ip in ips:
                    # Windows
                    windows_commands.append(f'netsh advfirewall firewall add rule name="IDS_Whitelist_{ip}" dir=in action=allow remoteip={ip}')
                    windows_commands.append(f'netsh advfirewall firewall add rule name="IDS_Whitelist_{ip}_out" dir=out action=allow remoteip={ip}')
                    # Linux
                    linux_commands.append(f'iptables -A INPUT -s {ip} -j ACCEPT')
                    linux_commands.append(f'iptables -A OUTPUT -d {ip} -j ACCEPT')
        
        elif strategy_type == "block":
            # 封禁策略
            if ip_range:
                ips = [ip.strip() for ip in ip_range.split(",")]
                for ip in ips:
                    dir_in = "in" if direction in ["inbound", "both"] else None
                    dir_out = "out" if direction in ["outbound", "both"] else None
                    
                    if dir_in:
                        windows_commands.append(f'netsh advfirewall firewall add rule name="IDS_Block_{ip}" dir=in action=block remoteip={ip}')
                        linux_commands.append(f'iptables -A INPUT -s {ip} -j DROP')
                    
                    if dir_out:
                        windows_commands.append(f'netsh advfirewall firewall add rule name="IDS_Block_{ip}_out" dir=out action=block remoteip={ip}')
                        linux_commands.append(f'iptables -A OUTPUT -d {ip} -j DROP')
                    
                    # 端口限制
                    if port_range:
                        ports = StrategyService.parse_port_range(port_range)
                        for port in ports:
                            if dir_in:
                                windows_commands.append(f'netsh advfirewall firewall add rule name="IDS_Block_{ip}_port_{port}" dir=in action=block remoteip={ip} localport={port} protocol=tcp')
                                linux_commands.append(f'iptables -A INPUT -s {ip} --dport {port} -j DROP')
                            if dir_out:
                                windows_commands.append(f'netsh advfirewall firewall add rule name="IDS_Block_{ip}_port_{port}_out" dir=out action=block remoteip={ip} remoteport={port} protocol=tcp')
                                linux_commands.append(f'iptables -A OUTPUT -d {ip} --dport {port} -j DROP')
        
        elif strategy_type == "throttle":
            # 限流策略
            if ip_range and packet_limit:
                ips = [ip.strip() for ip in ip_range.split(",")]
                for ip in ips:
                    # Linux限流使用iptables的limit模块
                    linux_commands.append(f'iptables -A INPUT -s {ip} -m limit --limit {packet_limit}/second -j ACCEPT')
                    linux_commands.append(f'iptables -A INPUT -s {ip} -j DROP')
                    
                    if port_range:
                        ports = StrategyService.parse_port_range(port_range)
                        for port in ports:
                            linux_commands.append(f'iptables -A INPUT -s {ip} --dport {port} -m limit --limit {packet_limit}/second -j ACCEPT')
                            linux_commands.append(f'iptables -A INPUT -s {ip} --dport {port} -j DROP')
                    
                    # Windows限流较复杂，使用基本规则
                    windows_commands.append(f'netsh advfirewall firewall add rule name="IDS_Throttle_{ip}" dir=in action=allow remoteip={ip}')
        
        return "; ".join(windows_commands), "; ".join(linux_commands)
    
    @staticmethod
    def parse_port_range(port_range_str: str) -> List[int]:
        ports = []
        if not port_range_str:
            return ports
        
        parts = port_range_str.split(",")
        for part in parts:
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        
        return ports
    
    @staticmethod
    def create_strategy(db: Session, strategy_data: ResponseStrategyCreate):
        # 生成防火墙命令
        win_cmd, linux_cmd = StrategyService.generate_firewall_commands(
            strategy_data.strategy_type,
            strategy_data.direction,
            strategy_data.ip_range,
            strategy_data.port_range,
            strategy_data.packet_limit
        )
        
        db_strategy = ResponseStrategy(
            name=strategy_data.name,
            strategy_type=strategy_data.strategy_type,
            direction=strategy_data.direction,
            ip_range=strategy_data.ip_range,
            port_range=strategy_data.port_range,
            packet_limit=strategy_data.packet_limit,
            command_windows=win_cmd,
            command_linux=linux_cmd,
            is_active=False,
            is_executed=False
        )
        db.add(db_strategy)
        db.commit()
        db.refresh(db_strategy)
        return db_strategy
    
    @staticmethod
    def execute_strategy(db: Session, strategy_id: int):
        strategy = db.query(ResponseStrategy).filter(ResponseStrategy.id == strategy_id).first()
        if not strategy:
            return None
        
        os_type = StrategyService.get_os_type()
        
        try:
            if os_type == "windows" and strategy.command_windows:
                commands = strategy.command_windows.split("; ")
                for cmd in commands:
                    subprocess.run(cmd, shell=True, check=True)
            elif os_type == "linux" and strategy.command_linux:
                commands = strategy.command_linux.split("; ")
                for cmd in commands:
                    subprocess.run(cmd, shell=True, check=True)
            
            strategy.is_active = True
            strategy.is_executed = True
            db.commit()
            db.refresh(strategy)
            return strategy
        except Exception as e:
            print(f"执行策略失败: {e}")
            return None
    
    @staticmethod
    def cancel_strategy(db: Session, strategy_id: int):
        strategy = db.query(ResponseStrategy).filter(ResponseStrategy.id == strategy_id).first()
        if not strategy or not strategy.is_active:
            return None
        
        os_type = StrategyService.get_os_type()
        
        try:
            # 删除防火墙规则
            if strategy.ip_range:
                ips = [ip.strip() for ip in strategy.ip_range.split(",")]
                for ip in ips:
                    if os_type == "windows":
                        subprocess.run(f'netsh advfirewall firewall delete rule name="IDS_Block_{ip}"', shell=True)
                        subprocess.run(f'netsh advfirewall firewall delete rule name="IDS_Block_{ip}_out"', shell=True)
                    elif os_type == "linux":
                        subprocess.run(f'iptables -D INPUT -s {ip} -j DROP', shell=True)
                        subprocess.run(f'iptables -D OUTPUT -d {ip} -j DROP', shell=True)
            
            strategy.is_active = False
            db.commit()
            db.refresh(strategy)
            return strategy
        except Exception as e:
            log_strategy(f"取消策略失败: {e}")
            return None
    
    @staticmethod
    def create_adaptive_strategy(db: Session, strategy_data: AdaptiveStrategyCreate):
        db_strategy = AdaptiveStrategy(
            name=strategy_data.name,
            threat_level=strategy_data.threat_level,
            attack_type=strategy_data.attack_type,
            action=strategy_data.action,
            block_duration=strategy_data.block_duration,
            packet_limit=strategy_data.packet_limit,
            is_active=True
        )
        db.add(db_strategy)
        db.commit()
        db.refresh(db_strategy)
        return db_strategy
    
    @staticmethod
    def execute_adaptive_strategy(db: Session, strategy: AdaptiveStrategy, target_ip: str):
        # 检查策略是否已启用
        if not strategy.is_active:
            return None
        
        # 检查是否已执行过
        existing = db.query(ExecutedStrategy).filter(
            and_(
                ExecutedStrategy.target_ip == target_ip,
                ExecutedStrategy.strategy_type == "adaptive",
                ExecutedStrategy.is_cancelled == False
            )
        ).first()
        
        if existing:
            return None
        
        # 生成注释
        annotation = f"自适应策略: {strategy.name}, 攻击类型: {strategy.attack_type}, 威胁级别: {strategy.threat_level}"
        
        if strategy.action == "alert":
            annotation += ", 动作: 仅告警"
        elif strategy.action == "block":
            annotation += f", 动作: 封禁{strategy.block_duration or '永久'}"
            # 执行封禁
            if StrategyService.get_os_type() == "windows":
                subprocess.run(f'netsh advfirewall firewall add rule name="IDS_Adaptive_Block_{target_ip}" dir=in action=block remoteip={target_ip}', shell=True)
            else:
                subprocess.run(f'iptables -A INPUT -s {target_ip} -j DROP', shell=True)
        elif strategy.action == "throttle":
            annotation += f", 动作: 限流{strategy.packet_limit}包/秒"
            # 执行限流
            if StrategyService.get_os_type() == "linux":
                subprocess.run(f'iptables -A INPUT -s {target_ip} -m limit --limit {strategy.packet_limit}/second -j ACCEPT', shell=True)
                subprocess.run(f'iptables -A INPUT -s {target_ip} -j DROP', shell=True)
        
        executed = ExecutedStrategy(
            strategy_id=strategy.id,
            strategy_type="adaptive",
            target_ip=target_ip,
            action=strategy.action,
            annotation=annotation,
            is_cancelled=False
        )
        db.add(executed)
        db.commit()
        db.refresh(executed)
        return executed
    
    @staticmethod
    def get_strategies(db: Session, skip: int = 0, limit: int = 100):
        return db.query(ResponseStrategy).offset(skip).limit(limit).all()
    
    @staticmethod
    def get_adaptive_strategies(db: Session, skip: int = 0, limit: int = 100, only_active: bool = False):
        """获取自适应策略列表
        
        Args:
            only_active: 如果为True，只返回启用的策略；如果为False，返回所有策略
        """
        query = db.query(AdaptiveStrategy)
        if only_active:
            query = query.filter(AdaptiveStrategy.is_active == True)
        return query.offset(skip).limit(limit).all()
    
    @staticmethod
    def toggle_adaptive_strategy(db: Session, strategy_id: int, is_active: bool):
        """启用或禁用自适应策略"""
        strategy = db.query(AdaptiveStrategy).filter(AdaptiveStrategy.id == strategy_id).first()
        if strategy:
            strategy.is_active = is_active
            db.commit()
            db.refresh(strategy)
            return strategy
        return None
    
    @staticmethod
    def get_executed_strategies(db: Session, skip: int = 0, limit: int = 100):
        return db.query(ExecutedStrategy).filter(ExecutedStrategy.is_cancelled == False).order_by(ExecutedStrategy.timestamp.desc()).offset(skip).limit(limit).all()
    
    @staticmethod
    def delete_strategy(db: Session, strategy_id: int):
        strategy = db.query(ResponseStrategy).filter(ResponseStrategy.id == strategy_id).first()
        if strategy:
            # 如果策略正在执行，先取消
            if strategy.is_active:
                StrategyService.cancel_strategy(db, strategy_id)
            db.delete(strategy)
            db.commit()
            return True
        return False
    
    @staticmethod
    def delete_adaptive_strategy(db: Session, strategy_id: int):
        strategy = db.query(AdaptiveStrategy).filter(AdaptiveStrategy.id == strategy_id).first()
        if strategy:
            db.delete(strategy)
            db.commit()
            return True
        return False
    
    @staticmethod
    def get_adaptive_strategy(db: Session, strategy_id: int):
        """获取单个自适应策略"""
        return db.query(AdaptiveStrategy).filter(AdaptiveStrategy.id == strategy_id).first()
    
    @staticmethod
    def update_adaptive_strategy(db: Session, strategy_id: int, strategy_data: AdaptiveStrategyCreate):
        """更新自适应策略"""
        strategy = db.query(AdaptiveStrategy).filter(AdaptiveStrategy.id == strategy_id).first()
        if not strategy:
            return None
        
        # 更新策略字段
        strategy.name = strategy_data.name
        strategy.threat_level = strategy_data.threat_level
        strategy.attack_type = strategy_data.attack_type
        strategy.action = strategy_data.action
        strategy.block_duration = strategy_data.block_duration
        strategy.packet_limit = strategy_data.packet_limit
        
        db.commit()
        db.refresh(strategy)
        return strategy
    
    @staticmethod
    def cancel_executed_strategy(db: Session, executed_id: int):
        executed = db.query(ExecutedStrategy).filter(ExecutedStrategy.id == executed_id).first()
        if executed and not executed.is_cancelled:
            # 取消防火墙规则
            if StrategyService.get_os_type() == "windows":
                subprocess.run(f'netsh advfirewall firewall delete rule name="IDS_Adaptive_Block_{executed.target_ip}"', shell=True)
            else:
                subprocess.run(f'iptables -D INPUT -s {executed.target_ip} -j DROP', shell=True)
            
            executed.is_cancelled = True
            db.commit()
            db.refresh(executed)
            return executed
        return None
    
    @staticmethod
    def find_matching_strategy(db: Session, attack_type: str, threat_level: str):
        """查找匹配的自适应策略
        
        匹配规则（精确匹配）：
        1. 策略必须启用 (is_active=True)
        2. 攻击类型匹配 (attack_type='all' 或与检测的攻击类型相同)
        3. 威胁级别精确匹配 (threat_level == 检测的威胁级别)
        """
        # 首先查找精确匹配（攻击类型和威胁级别都精确匹配）
        strategy = db.query(AdaptiveStrategy).filter(
            and_(
                AdaptiveStrategy.is_active == True,
                AdaptiveStrategy.attack_type == attack_type,
                AdaptiveStrategy.threat_level == threat_level
            )
        ).first()
        
        if strategy:
            log_strategy(f"[策略匹配] 精确匹配成功: {strategy.name} (攻击类型: {attack_type}, 威胁级别: {threat_level})")
            return strategy
        
        # 查找攻击类型为'all'且威胁级别精确匹配的策略
        strategy = db.query(AdaptiveStrategy).filter(
            and_(
                AdaptiveStrategy.is_active == True,
                AdaptiveStrategy.attack_type == 'all',
                AdaptiveStrategy.threat_level == threat_level
            )
        ).first()
        
        if strategy:
            log_strategy(f"[策略匹配] 通配匹配成功: {strategy.name} (攻击类型: all, 威胁级别: {threat_level})")
            return strategy
        
        log_strategy(f"[策略匹配] 未找到匹配策略 (攻击类型: {attack_type}, 威胁级别: {threat_level})")
        return None
    
    @staticmethod
    def auto_execute_strategy(db: Session, attack_type: str, threat_level: str, src_ip: str):
        """自动执行匹配的自适应策略
        
        Args:
            db: 数据库会话
            attack_type: 攻击类型
            threat_level: 威胁级别
            src_ip: 源IP地址
        
        Returns:
            执行的策略信息，如果没有匹配则返回None
        """
        # 检查IP是否在白名单中
        from app.models.strategy import WhitelistIP
        is_whitelisted = db.query(WhitelistIP).filter(WhitelistIP.ip_address == src_ip).first()
        if is_whitelisted:
            log_strategy(f"[策略跳过] IP {src_ip} 在白名单中，跳过响应策略")
            return None
        
        # BENIGN类型不执行任何策略
        if attack_type == "BENIGN" or threat_level == "none":
            log_strategy(f"[策略跳过] 攻击类型: {attack_type}, 威胁级别: {threat_level}")
            return None
        
        log_strategy(f"[策略匹配] 尝试匹配策略 - 攻击类型: {attack_type}, 威胁级别: {threat_level}, 源IP: {src_ip}")
        
        # 查找匹配的策略
        strategy = StrategyService.find_matching_strategy(db, attack_type, threat_level)
        
        if not strategy:
            return None
        
        log_strategy(f"[策略匹配] 找到匹配策略: {strategy.name}, 动作: {strategy.action}")
        
        # 执行策略
        result = StrategyService.execute_adaptive_strategy(db, strategy, src_ip)
        
        if result:
            log_strategy(f"[策略执行] 成功执行策略: {strategy.name}")
            return {
                "strategy_name": strategy.name,
                "action": strategy.action,
                "executed_id": result.id
            }
        
        log_strategy(f"[策略执行] 策略执行失败或已存在")
        return None
