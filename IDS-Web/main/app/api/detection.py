from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.database import get_db
from app.api.auth import get_current_user
from app.services.detection_service import DetectionService
from app.schemas.detection import DetectionResultResponse, DetectionFilter, DetectionStats, DetectionDetail

router = APIRouter()

@router.get("/list")
def get_detection_list(
    skip: int = 0,
    limit: int = 100,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    attack_type: Optional[str] = None,
    threat_level: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """获取检测结果列表"""
    filters = DetectionFilter(
        src_ip=src_ip,
        dst_ip=dst_ip,
        attack_type=attack_type,
        threat_level=threat_level
    )
    
    detections = DetectionService.get_detection_list(db, skip, limit, filters)
    return detections

@router.get("/stats")
def get_detection_stats(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """获取检测统计"""
    stats = DetectionService.get_detection_stats(db)
    return stats

@router.get("/threat-distribution")
def get_threat_distribution(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """获取威胁级别分布"""
    distribution = DetectionService.get_threat_distribution(db)
    return {"distribution": distribution}

@router.get("/attack-type-distribution")
def get_attack_type_distribution(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """获取攻击类型分布"""
    distribution = DetectionService.get_attack_type_distribution(db)
    return {"distribution": distribution}

@router.get("/malicious-list")
def get_malicious_list(
    skip: int = 0,
    limit: int = 100,
    include_whitelist: bool = False,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """获取包含威胁的流量列表（低危、中危、高危）"""
    from app.models.detection import DetectionResult
    
    query = db.query(DetectionResult).filter(
        DetectionResult.threat_level.in_(["low", "medium", "high"])
    )
    
    # 如果不包含白名单，则排除白名单中的IP
    if not include_whitelist:
        from app.models.strategy import WhitelistIP
        whitelist_ips = db.query(WhitelistIP.ip_address).all()
        whitelist_ip_list = [ip[0] for ip in whitelist_ips]
        if whitelist_ip_list:
            query = query.filter(~DetectionResult.src_ip.in_(whitelist_ip_list))
    
    detections = query.order_by(DetectionResult.timestamp.desc()).offset(skip).limit(limit).all()
    total = query.count()
    
    return {
        "items": detections,
        "total": total
    }

@router.get("/detail/{detection_id}")
def get_detection_detail(
    detection_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """获取检测详情"""
    from app.services.threat_scorer import evaluate_threat, get_threat_level_chinese
    
    detection = DetectionService.get_detection_by_id(db, detection_id)
    if not detection:
        return {"error": "未找到检测结果"}
    
    # 计算威胁分数
    score, level, level_chinese = evaluate_threat(detection.attack_type, detection.confidence)
    
    return {
        "id": detection.id,
        "timestamp": detection.timestamp,
        "src_ip": detection.src_ip,
        "src_port": detection.src_port,
        "dst_ip": detection.dst_ip,
        "dst_port": detection.dst_port,
        "protocol": detection.protocol,
        "attack_type": detection.attack_type,
        "confidence": detection.confidence,
        "threat_level": detection.threat_level,
        "threat_level_chinese": level_chinese,
        "threat_score": score,
        "response_strategy": detection.response_strategy,
        "weight_calculation": f"Score: {score:.4f}, 威胁等级: {level_chinese}, 置信度: {detection.confidence:.4f}"
    }

@router.post("/handle/{detection_id}")
def handle_detection(
    detection_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """标记检测为已处理"""
    detection = DetectionService.mark_as_handled(db, detection_id)
    if detection:
        return {"success": True, "message": "已标记为处理"}
    return {"success": False, "message": "未找到检测结果"}

@router.delete("/clear-malicious")
def clear_malicious_traffic(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """清空恶意流量列表"""
    count = DetectionService.clear_malicious_traffic(db)
    return {"success": True, "message": f"已清空 {count} 条恶意流量记录"}

@router.delete("/clear-all")
def clear_all_detections(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """清空所有检测结果"""
    count = DetectionService.clear_all_detections(db)
    return {"success": True, "message": f"已清空 {count} 条检测记录"}
