from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional

class DashboardStats(BaseModel):
    total_traffic: int
    abnormal_traffic: int
    threat_detections: int
    response_strategies: int
    total_traffic_new: int
    abnormal_traffic_new: int
    threat_detections_new: int
    response_strategies_new: int

class TrafficTrend(BaseModel):
    time_label: str
    normal_count: int
    abnormal_count: int

class RecentDetection(BaseModel):
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

class DashboardData(BaseModel):
    stats: DashboardStats
    traffic_trend: List[TrafficTrend]
    recent_detections: List[RecentDetection]
