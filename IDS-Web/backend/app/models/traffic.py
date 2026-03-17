from sqlalchemy import Column, Integer, String, DateTime, Float, BigInteger
from sqlalchemy.sql import func
from app.core.database import Base

class Traffic(Base):
    __tablename__ = "traffic"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    src_ip = Column(String(50), index=True)
    src_port = Column(Integer)
    dst_ip = Column(String(50), index=True)
    dst_port = Column(Integer)
    protocol = Column(String(20))
    packet_size = Column(BigInteger)
    flow_duration = Column(Float)
    status = Column(String(20), default="normal")  # normal/abnormal
    attack_type = Column(String(50), nullable=True)
    confidence = Column(Float, nullable=True)
    
    # 28个特征值字段
    fwd_packets = Column(Integer, default=0)
    bwd_packets = Column(Integer, default=0)
    fwd_bytes = Column(BigInteger, default=0)
    bwd_bytes = Column(BigInteger, default=0)
    fwd_pkt_len_max = Column(Float, default=0)
    fwd_pkt_len_min = Column(Float, default=0)
    fwd_pkt_len_mean = Column(Float, default=0)
    bwd_pkt_len_max = Column(Float, default=0)
    bwd_pkt_len_min = Column(Float, default=0)
    bwd_pkt_len_mean = Column(Float, default=0)
    flow_bytes_s = Column(Float, default=0)
    flow_packets_s = Column(Float, default=0)
    fwd_header_len = Column(Integer, default=0)
    bwd_header_len = Column(Integer, default=0)
    fwd_packets_s = Column(Float, default=0)
    bwd_packets_s = Column(Float, default=0)
    min_pkt_len = Column(Float, default=0)
    max_pkt_len = Column(Float, default=0)
    pkt_len_mean = Column(Float, default=0)
    pkt_len_std = Column(Float, default=0)
    pkt_len_var = Column(Float, default=0)
    fwd_iat_mean = Column(Float, default=0)
    bwd_iat_mean = Column(Float, default=0)
    active_mean = Column(Float, default=0)
    idle_mean = Column(Float, default=0)
    min_idle = Column(Float, default=0)
    max_idle = Column(Float, default=0)
