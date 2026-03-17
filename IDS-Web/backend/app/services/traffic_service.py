from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from datetime import datetime, timedelta
from typing import List, Optional
from app.models.traffic import Traffic
from app.schemas.traffic import TrafficFilter
from app.core.logger import log_detection

class TrafficService:
    @staticmethod
    def create_traffic(db: Session, traffic_data: dict):
        try:
            db_traffic = Traffic(**traffic_data)
            db.add(db_traffic)
            db.commit()
            db.refresh(db_traffic)
            log_detection(f"流量记录已保存到数据库，ID: {db_traffic.id}")
            return db_traffic
        except Exception as e:
            log_detection(f"保存流量记录失败: {e}")
            db.rollback()
            raise
    
    @staticmethod
    def get_traffic_list(db: Session, skip: int = 0, limit: int = 100, filters: TrafficFilter = None):
        query = db.query(Traffic)
        
        if filters:
            if filters.start_time:
                query = query.filter(Traffic.timestamp >= filters.start_time)
            if filters.end_time:
                query = query.filter(Traffic.timestamp <= filters.end_time)
            if filters.src_ip:
                query = query.filter(Traffic.src_ip == filters.src_ip)
            if filters.src_port:
                query = query.filter(Traffic.src_port == filters.src_port)
            if filters.dst_ip:
                query = query.filter(Traffic.dst_ip == filters.dst_ip)
            if filters.dst_port:
                query = query.filter(Traffic.dst_port == filters.dst_port)
            if filters.protocol:
                query = query.filter(Traffic.protocol == filters.protocol)
            if filters.attack_type:
                query = query.filter(Traffic.attack_type == filters.attack_type)
            if filters.status:
                query = query.filter(Traffic.status == filters.status)
        
        return query.order_by(Traffic.timestamp.desc()).offset(skip).limit(limit).all()
    
    @staticmethod
    def get_traffic_count(db: Session, filters: TrafficFilter = None):
        query = db.query(func.count(Traffic.id))
        
        if filters:
            if filters.start_time:
                query = query.filter(Traffic.timestamp >= filters.start_time)
            if filters.end_time:
                query = query.filter(Traffic.timestamp <= filters.end_time)
            if filters.src_ip:
                query = query.filter(Traffic.src_ip == filters.src_ip)
            if filters.src_port:
                query = query.filter(Traffic.src_port == filters.src_port)
            if filters.dst_ip:
                query = query.filter(Traffic.dst_ip == filters.dst_ip)
            if filters.dst_port:
                query = query.filter(Traffic.dst_port == filters.dst_port)
            if filters.protocol:
                query = query.filter(Traffic.protocol == filters.protocol)
            if filters.attack_type:
                query = query.filter(Traffic.attack_type == filters.attack_type)
            if filters.status:
                query = query.filter(Traffic.status == filters.status)
        
        return query.scalar()
    
    @staticmethod
    def get_traffic_stats(db: Session, hours: int = 1):
        start_time = datetime.now() - timedelta(hours=hours)
        
        total = db.query(Traffic).filter(Traffic.timestamp >= start_time).count()
        abnormal = db.query(Traffic).filter(
            and_(Traffic.timestamp >= start_time, Traffic.status == "abnormal")
        ).count()
        
        return {"total": total, "abnormal": abnormal}
    
    @staticmethod
    def get_traffic_trend(db: Session, hours: int = 1):
        start_time = datetime.now() - timedelta(hours=hours)
        
        # 按10分钟分组统计
        results = db.query(
            func.date_format(Traffic.timestamp, '%H:%i').label('time_label'),
            func.count().label('count'),
            func.sum(func.if_(Traffic.status == 'abnormal', 1, 0)).label('abnormal_count')
        ).filter(Traffic.timestamp >= start_time).group_by(
            func.floor(func.unix_timestamp(Traffic.timestamp) / 600)
        ).all()
        
        trend_data = []
        for result in results:
            trend_data.append({
                "time_label": result.time_label,
                "normal_count": result.count - result.abnormal_count,
                "abnormal_count": result.abnormal_count
            })
        
        return trend_data
    
    @staticmethod
    def get_protocol_distribution(db: Session, hours: int = 1):
        start_time = datetime.now() - timedelta(hours=hours)
        
        results = db.query(
            Traffic.protocol,
            func.count().label('count')
        ).filter(Traffic.timestamp >= start_time).group_by(Traffic.protocol).all()
        
        return [{"protocol": r.protocol, "count": r.count} for r in results]
    
    @staticmethod
    def get_attack_distribution(db: Session, hours: int = 1):
        start_time = datetime.now() - timedelta(hours=hours)
        
        results = db.query(
            Traffic.status,
            func.count().label('count')
        ).filter(
            Traffic.timestamp >= start_time
        ).group_by(Traffic.status).all()
        
        # 转换状态为中文
        status_map = {
            "normal": "正常流量",
            "abnormal": "异常流量"
        }
        
        return [{"attack_type": status_map.get(r.status, "未知"), "count": r.count} for r in results]
    
    @staticmethod
    def get_src_ip_distribution(db: Session, hours: int = 1):
        start_time = datetime.now() - timedelta(hours=hours)
        
        results = db.query(
            Traffic.src_ip,
            func.count().label('count')
        ).filter(
            Traffic.timestamp >= start_time
        ).group_by(Traffic.src_ip).order_by(func.count().desc()).limit(10).all()
        
        return [{"src_ip": r.src_ip, "count": r.count} for r in results]
    
    @staticmethod
    def get_dst_ip_distribution(db: Session, hours: int = 1):
        start_time = datetime.now() - timedelta(hours=hours)
        
        results = db.query(
            Traffic.dst_ip,
            func.count().label('count')
        ).filter(
            Traffic.timestamp >= start_time
        ).group_by(Traffic.dst_ip).order_by(func.count().desc()).limit(10).all()
        
        return [{"dst_ip": r.dst_ip, "count": r.count} for r in results]
    
    @staticmethod
    def get_dst_port_distribution(db: Session, hours: int = 1):
        start_time = datetime.now() - timedelta(hours=hours)
        
        results = db.query(
            Traffic.dst_port,
            func.count().label('count')
        ).filter(
            Traffic.timestamp >= start_time
        ).group_by(Traffic.dst_port).order_by(func.count().desc()).limit(10).all()
        
        return [{"dst_port": r.dst_port, "count": r.count} for r in results]
    
    @staticmethod
    def clear_all_traffic(db: Session) -> int:
        """清空所有流量数据"""
        count = db.query(Traffic).count()
        db.query(Traffic).delete()
        db.commit()
        return count
