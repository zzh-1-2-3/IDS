from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

class DetectionResultResponse(BaseModel):
    id: int
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packet_size: int
    attack_type: str
    confidence: float
    threat_level: str
    response_strategy: Optional[str] = None
    is_handled: int
    
    class Config:
        from_attributes = True

class DetectionFilter(BaseModel):
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    attack_type: Optional[str] = None
    threat_level: Optional[str] = None

class DetectionStats(BaseModel):
    total_packets: int
    high_risk: int
    medium_risk: int
    low_risk: int
    high_risk_new: int
    medium_risk_new: int
    low_risk_new: int

class ThreatDistribution(BaseModel):
    high: int
    medium: int
    low: int

class AttackTypeDistribution(BaseModel):
    attack_type: str
    count: int
    percentage: float

class DetectionDetail(BaseModel):
    id: int
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    attack_type: str
    confidence: float
    threat_level: str
    weight_calculation: Optional[str] = None
    response_strategy: Optional[str] = None
