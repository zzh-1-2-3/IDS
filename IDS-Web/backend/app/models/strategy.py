from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.sql import func
from app.core.database import Base

class ResponseStrategy(Base):
    __tablename__ = "response_strategies"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    strategy_type = Column(String(50), nullable=False)  # block/throttle/whitelist
    direction = Column(String(20), nullable=True)  # inbound/outbound
    ip_range = Column(Text, nullable=True)  # IP或网段，逗号分隔
    port_range = Column(Text, nullable=True)  # 端口范围，如 "80,443,100-200"
    packet_limit = Column(Integer, nullable=True)  # 限流时的包数/秒
    is_active = Column(Boolean, default=False)
    is_executed = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    command_windows = Column(Text, nullable=True)  # Windows防火墙命令
    command_linux = Column(Text, nullable=True)  # Linux iptables命令

class AdaptiveStrategy(Base):
    __tablename__ = "adaptive_strategies"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    threat_level = Column(String(20), nullable=False)  # high/medium/low
    attack_type = Column(String(50), nullable=False)  # all/Bot/BruteForce/DoS/...
    action = Column(String(50), nullable=False)  # block/throttle/alert
    block_duration = Column(String(20), nullable=True)  # 1h/24h/permanent
    packet_limit = Column(Integer, nullable=True)  # 限流时的包数/秒
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class ExecutedStrategy(Base):
    __tablename__ = "executed_strategies"
    
    id = Column(Integer, primary_key=True, index=True)
    strategy_id = Column(Integer)
    strategy_type = Column(String(50))  # custom/adaptive
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    target_ip = Column(String(50))
    action = Column(String(50))
    annotation = Column(Text)  # 策略注释
    is_cancelled = Column(Boolean, default=False)

class WhitelistIP(Base):
    __tablename__ = "whitelist_ips"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(50), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
