from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

class TrafficCreate(BaseModel):
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packet_size: int
    flow_duration: float
    
class TrafficResponse(BaseModel):
    id: int
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packet_size: int
    status: str
    attack_type: Optional[str] = None
    confidence: Optional[float] = None
    
    class Config:
        from_attributes = True

class TrafficFilter(BaseModel):
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    attack_type: Optional[str] = None
    status: Optional[str] = None

class TrafficTrendData(BaseModel):
    time_label: str
    normal_count: int
    abnormal_count: int

class RealtimeTraffic(BaseModel):
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packet_size: int
    status: str
    attack_type: Optional[str] = None
    confidence: Optional[float] = None
