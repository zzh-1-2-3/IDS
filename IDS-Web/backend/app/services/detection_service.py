from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from datetime import datetime, timedelta
from typing import List, Optional
from app.models.detection import DetectionResult
from app.schemas.detection import DetectionFilter
from app.core.logger import log_detection

class DetectionService:
    @staticmethod
    def create_detection(db: Session, detection_data: dict):
        try:
            db_detection = DetectionResult(**detection_data)
            db.add(db_detection)
            db.commit()
            db.refresh(db_detection)
            log_detection(f"检测结果记录已保存到数据库，ID: {db_detection.id}")
            return db_detection
        except Exception as e:
            log_detection(f"保存检测结果记录失败: {e}")
            db.rollback()
            raise
    
    @staticmethod
    def get_detection_list(db: Session, skip: int = 0, limit: int = 100, filters: DetectionFilter = None):
        query = db.query(DetectionResult)
        
        # 排除白名单中的IP
        from app.models.strategy import WhitelistIP
        whitelist_ips = db.query(WhitelistIP.ip_address).all()
        whitelist_ip_list = [ip[0] for ip in whitelist_ips]
        if whitelist_ip_list:
            query = query.filter(~DetectionResult.src_ip.in_(whitelist_ip_list))
        
        if filters:
            if filters.start_time:
                query = query.filter(DetectionResult.timestamp >= filters.start_time)
            if filters.end_time:
                query = query.filter(DetectionResult.timestamp <= filters.end_time)
            if filters.src_ip:
                query = query.filter(DetectionResult.src_ip == filters.src_ip)
            if filters.dst_ip:
                query = query.filter(DetectionResult.dst_ip == filters.dst_ip)
            if filters.attack_type:
                query = query.filter(DetectionResult.attack_type == filters.attack_type)
            if filters.threat_level:
                query = query.filter(DetectionResult.threat_level == filters.threat_level)
        
        return query.order_by(DetectionResult.timestamp.desc()).offset(skip).limit(limit).all()
    
    @staticmethod
    def get_detection_stats(db: Session, hours: int = 24):
        start_time = datetime.now() - timedelta(hours=hours)
        
        total = db.query(DetectionResult).filter(DetectionResult.timestamp >= start_time).count()
        high_risk = db.query(DetectionResult).filter(
            and_(DetectionResult.timestamp >= start_time, DetectionResult.threat_level == "high")
        ).count()
        medium_risk = db.query(DetectionResult).filter(
            and_(DetectionResult.timestamp >= start_time, DetectionResult.threat_level == "medium")
        ).count()
        low_risk = db.query(DetectionResult).filter(
            and_(DetectionResult.timestamp >= start_time, DetectionResult.threat_level == "low")
        ).count()
        no_risk = db.query(DetectionResult).filter(
            and_(DetectionResult.timestamp >= start_time, DetectionResult.threat_level == "none")
        ).count()
        
        # 计算异常流量总数（非BENIGN）
        abnormal_flows = db.query(DetectionResult).filter(
            and_(DetectionResult.timestamp >= start_time, DetectionResult.attack_type != "BENIGN")
        ).count()
        
        # 计算新增数量（最近1小时）
        recent_time = datetime.now() - timedelta(hours=1)
        high_risk_new = db.query(DetectionResult).filter(
            and_(DetectionResult.timestamp >= recent_time, DetectionResult.threat_level == "high")
        ).count()
        medium_risk_new = db.query(DetectionResult).filter(
            and_(DetectionResult.timestamp >= recent_time, DetectionResult.threat_level == "medium")
        ).count()
        low_risk_new = db.query(DetectionResult).filter(
            and_(DetectionResult.timestamp >= recent_time, DetectionResult.threat_level == "low")
        ).count()
        no_risk_new = db.query(DetectionResult).filter(
            and_(DetectionResult.timestamp >= recent_time, DetectionResult.threat_level == "none")
        ).count()
        abnormal_flows_new = db.query(DetectionResult).filter(
            and_(DetectionResult.timestamp >= recent_time, DetectionResult.attack_type != "BENIGN")
        ).count()
        
        return {
            "total_flows": total,
            "abnormal_flows": abnormal_flows,
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk,
            "no_risk": no_risk,
            "high_risk_new": high_risk_new,
            "medium_risk_new": medium_risk_new,
            "low_risk_new": low_risk_new,
            "no_risk_new": no_risk_new,
            "abnormal_flows_new": abnormal_flows_new
        }
    
    @staticmethod
    def get_threat_distribution(db: Session, hours: int = 24):
        start_time = datetime.now() - timedelta(hours=hours)
        
        results = db.query(
            DetectionResult.threat_level,
            func.count().label('count')
        ).filter(DetectionResult.timestamp >= start_time).group_by(DetectionResult.threat_level).all()
        
        distribution = {"high": 0, "medium": 0, "low": 0, "none": 0}
        for r in results:
            if r.threat_level in distribution:
                distribution[r.threat_level] = r.count
        
        return distribution
    
    @staticmethod
    def get_attack_type_distribution(db: Session, hours: int = 24):
        start_time = datetime.now() - timedelta(hours=hours)
        
        total = db.query(DetectionResult).filter(DetectionResult.timestamp >= start_time).count()
        
        results = db.query(
            DetectionResult.attack_type,
            func.count().label('count')
        ).filter(DetectionResult.timestamp >= start_time).group_by(DetectionResult.attack_type).all()
        
        distribution = []
        for r in results:
            percentage = (r.count / total * 100) if total > 0 else 0
            distribution.append({
                "attack_type": r.attack_type,
                "count": r.count,
                "percentage": round(percentage, 2)
            })
        
        return distribution
    
    @staticmethod
    def get_detection_by_id(db: Session, detection_id: int):
        return db.query(DetectionResult).filter(DetectionResult.id == detection_id).first()
    
    @staticmethod
    def mark_as_handled(db: Session, detection_id: int):
        detection = db.query(DetectionResult).filter(DetectionResult.id == detection_id).first()
        if detection:
            detection.is_handled = 1
            db.commit()
            db.refresh(detection)
        return detection
    
    @staticmethod
    def clear_malicious_traffic(db: Session):
        count = db.query(DetectionResult).filter(DetectionResult.attack_type != "BENIGN").delete()
        db.commit()
        return count
    
    @staticmethod
    def clear_all_detections(db: Session):
        count = db.query(DetectionResult).delete()
        db.commit()
        return count
