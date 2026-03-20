from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

class ResponseStrategyCreate(BaseModel):
    name: str
    strategy_type: str  # block/throttle/whitelist
    direction: Optional[str] = None  # inbound/outbound
    ip_range: Optional[str] = None
    port_range: Optional[str] = None
    packet_limit: Optional[int] = None

class ResponseStrategyResponse(BaseModel):
    id: int
    name: str
    strategy_type: str
    direction: Optional[str] = None
    ip_range: Optional[str] = None
    port_range: Optional[str] = None
    packet_limit: Optional[int] = None
    is_active: bool
    is_executed: bool
    created_at: datetime
    command_windows: Optional[str] = None
    command_linux: Optional[str] = None
    
    class Config:
        from_attributes = True

class AdaptiveStrategyCreate(BaseModel):
    name: str
    threat_level: str  # high/medium/low
    attack_type: str  # all/Bot/BruteForce/DoS/...
    action: str  # block/throttle/alert
    block_duration: Optional[str] = None  # 1h/24h/permanent
    packet_limit: Optional[int] = None

class AdaptiveStrategyResponse(BaseModel):
    id: int
    name: str
    threat_level: str
    attack_type: str
    action: str
    block_duration: Optional[str] = None
    packet_limit: Optional[int] = None
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class ExecutedStrategyResponse(BaseModel):
    id: int
    strategy_id: int
    strategy_type: str
    timestamp: datetime
    target_ip: str
    action: str
    annotation: str
    is_cancelled: bool
    
    class Config:
        from_attributes = True

class SystemInfo(BaseModel):
    os_type: str  # windows/linux
    version: str

class WhitelistIPRequest(BaseModel):
    ip: str
