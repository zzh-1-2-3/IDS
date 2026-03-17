from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timedelta

from app.core.database import get_db
from app.api.auth import get_current_user
from app.services.traffic_service import TrafficService
from app.services.detection_service import DetectionService
from app.services.strategy_service import StrategyService
from app.schemas.dashboard import DashboardStats, TrafficTrend, DashboardData
from app.models.traffic import Traffic
from app.models.detection import DetectionResult
from app.models.strategy import ResponseStrategy, AdaptiveStrategy

router = APIRouter()

@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """获取仪表盘统计数据"""
    # 获取流量统计（最近1小时）
    traffic_stats = TrafficService.get_traffic_stats(db, hours=1)
    
    # 获取检测统计（最近1小时）
    detection_stats = DetectionService.get_detection_stats(db, hours=1)
    
    # 获取响应策略数量（包括自定义策略和自适应策略）
    custom_strategy_count = db.query(ResponseStrategy).count()
    adaptive_strategy_count = db.query(AdaptiveStrategy).count()
    strategy_count = custom_strategy_count + adaptive_strategy_count
    
    # 获取正在执行的策略数量（已拦截目标数）
    from app.models.strategy import ExecutedStrategy
    executed_strategy_count = db.query(ExecutedStrategy).filter(ExecutedStrategy.is_cancelled == False).count()
    
    # 计算新增数量（最近1小时）
    recent_time = datetime.now() - timedelta(hours=1)
    
    total_traffic_new = db.query(Traffic).filter(Traffic.timestamp >= recent_time).count()
    abnormal_traffic_new = db.query(Traffic).filter(
        Traffic.timestamp >= recent_time, Traffic.status == "abnormal"
    ).count()
    response_strategies_new = 0  # 策略新增数量
    
    # 计算最近1小时新增的已拦截目标数
    executed_strategy_new = db.query(ExecutedStrategy).filter(
        ExecutedStrategy.timestamp >= recent_time,
        ExecutedStrategy.is_cancelled == False
    ).count()
    
    return DashboardStats(
        total_traffic=traffic_stats["total"],
        abnormal_traffic=traffic_stats["abnormal"],
        threat_detections=executed_strategy_count,
        response_strategies=strategy_count,
        total_traffic_new=total_traffic_new,
        abnormal_traffic_new=abnormal_traffic_new,
        threat_detections_new=executed_strategy_new,
        response_strategies_new=response_strategies_new
    )

@router.get("/traffic-trend", response_model=List[TrafficTrend])
def get_traffic_trend(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """获取近10分钟流量趋势（每2分钟为一格）"""
    start_time = datetime.now() - timedelta(minutes=10)
    
    # 生成5个时间点（每2分钟一个）
    trends = []
    for i in range(5):
        time_point = start_time + timedelta(minutes=i*2)
        next_time_point = time_point + timedelta(minutes=2)
        
        normal_count = db.query(Traffic).filter(
            Traffic.timestamp >= time_point,
            Traffic.timestamp < next_time_point,
            Traffic.status == "normal"
        ).count()
        
        abnormal_count = db.query(Traffic).filter(
            Traffic.timestamp >= time_point,
            Traffic.timestamp < next_time_point,
            Traffic.status == "abnormal"
        ).count()
        
        trends.append(TrafficTrend(
            time_label=time_point.strftime("%H:%M"),
            normal_count=normal_count,
            abnormal_count=abnormal_count
        ))
    
    return trends

@router.get("/recent-detections")
def get_recent_detections(limit: int = 7, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """获取最近检测结果（滚动显示）"""
    detections = db.query(DetectionResult).order_by(
        DetectionResult.timestamp.desc()
    ).limit(limit).all()
    
    result = []
    for d in detections:
        result.append({
            "id": d.id,
            "timestamp": d.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": d.src_ip,
            "src_port": d.src_port,
            "dst_ip": d.dst_ip,
            "dst_port": d.dst_port,
            "protocol": d.protocol,
            "packet_size": d.packet_size,
            "status": "abnormal" if d.attack_type != "BENIGN" else "normal",
            "attack_type": d.attack_type
        })
    
    return result

@router.get("/full-data", response_model=DashboardData)
def get_full_dashboard_data(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """获取完整仪表盘数据"""
    stats = get_dashboard_stats(db, current_user)
    trend = get_traffic_trend(db, current_user)
    recent = get_recent_detections(7, db, current_user)
    
    return DashboardData(
        stats=stats,
        traffic_trend=trend,
        recent_detections=recent
    )
