from sqlalchemy import Column, Integer, String, DateTime, Float, BigInteger, Text
from sqlalchemy.sql import func
from app.core.database import Base

class DetectionResult(Base):
    __tablename__ = "detection_results"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    src_ip = Column(String(50), index=True)
    src_port = Column(Integer)
    dst_ip = Column(String(50), index=True)
    dst_port = Column(Integer)
    protocol = Column(String(20))
    packet_size = Column(BigInteger)
    attack_type = Column(String(50))
    confidence = Column(Float)
    threat_level = Column(String(20))  # high/medium/low
    response_strategy = Column(String(255), nullable=True)
    is_handled = Column(Integer, default=0)  # 0-未处理 1-已处理
    details = Column(Text, nullable=True)
