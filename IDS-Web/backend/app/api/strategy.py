from fastapi import APIRouter, Depends, Body, Request
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.api.auth import get_current_user
from app.services.strategy_service import StrategyService
from app.schemas.strategy import (
    ResponseStrategyCreate, ResponseStrategyResponse,
    AdaptiveStrategyCreate, AdaptiveStrategyResponse,
    SystemInfo, WhitelistIPRequest
)

router = APIRouter()

@router.get("/os-type")
def get_os_type(current_user = Depends(get_current_user)):
    """获取操作系统类型"""
    import platform
    return {
        "os_type": StrategyService.get_os_type(),
        "version": platform.version()
    }

# 自定义策略API
@router.get("/custom/list")
def get_custom_strategies(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """获取自定义策略列表"""
    strategies = StrategyService.get_strategies(db, skip, limit)
    return strategies

@router.post("/custom/create")
def create_custom_strategy(
    strategy: ResponseStrategyCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """创建自定义策略"""
    db_strategy = StrategyService.create_strategy(db, strategy)
    return {"success": True, "strategy": db_strategy}

@router.post("/custom/execute/{strategy_id}")
def execute_custom_strategy(
    strategy_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """执行自定义策略"""
    result = StrategyService.execute_strategy(db, strategy_id)
    if result:
        return {"success": True, "message": "策略执行成功"}
    return {"success": False, "message": "策略执行失败"}

@router.post("/custom/cancel/{strategy_id}")
def cancel_custom_strategy(
    strategy_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """取消自定义策略"""
    result = StrategyService.cancel_strategy(db, strategy_id)
    if result:
        return {"success": True, "message": "策略已取消"}
    return {"success": False, "message": "策略取消失败"}

@router.delete("/custom/delete/{strategy_id}")
def delete_custom_strategy(
    strategy_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """删除自定义策略"""
    result = StrategyService.delete_strategy(db, strategy_id)
    if result:
        return {"success": True, "message": "策略已删除"}
    return {"success": False, "message": "策略删除失败"}

# 自适应策略API
@router.get("/adaptive/list")
def get_adaptive_strategies(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """获取自适应策略列表"""
    strategies = StrategyService.get_adaptive_strategies(db, skip, limit)
    return strategies

@router.post("/adaptive/create")
def create_adaptive_strategy(
    strategy: AdaptiveStrategyCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """创建自适应策略"""
    db_strategy = StrategyService.create_adaptive_strategy(db, strategy)
    return {"success": True, "strategy": db_strategy}

@router.delete("/adaptive/delete/{strategy_id}")
def delete_adaptive_strategy(
    strategy_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """删除自适应策略"""
    result = StrategyService.delete_adaptive_strategy(db, strategy_id)
    if result:
        return {"success": True, "message": "策略已删除"}
    return {"success": False, "message": "策略删除失败"}

@router.get("/adaptive/{strategy_id}")
def get_adaptive_strategy(
    strategy_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """获取单个自适应策略详情"""
    strategy = StrategyService.get_adaptive_strategy(db, strategy_id)
    if strategy:
        return strategy
    return {"success": False, "message": "策略不存在"}

@router.put("/adaptive/update/{strategy_id}")
def update_adaptive_strategy(
    strategy_id: int,
    strategy: AdaptiveStrategyCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """更新自适应策略"""
    result = StrategyService.update_adaptive_strategy(db, strategy_id, strategy)
    if result:
        return {"success": True, "message": "策略更新成功", "strategy": result}
    return {"success": False, "message": "策略更新失败"}

@router.post("/adaptive/toggle/{strategy_id}")
def toggle_adaptive_strategy(
    strategy_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """切换自适应策略的启用/禁用状态"""
    # 先获取当前策略状态
    strategy = StrategyService.get_adaptive_strategy(db, strategy_id)
    if not strategy:
        return {"success": False, "message": "策略不存在"}
    
    # 切换状态
    new_status = not strategy.is_active
    result = StrategyService.toggle_adaptive_strategy(db, strategy_id, new_status)
    if result:
        status_text = "启用" if new_status else "禁用"
        return {"success": True, "message": f"策略已{status_text}", "is_active": new_status}
    return {"success": False, "message": "操作失败"}

# 正在执行的策略API
@router.get("/executed/list")
def get_executed_strategies(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """获取正在执行的策略列表"""
    strategies = StrategyService.get_executed_strategies(db, skip, limit)
    return strategies

@router.post("/executed/cancel/{executed_id}")
def cancel_executed_strategy(
    executed_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """取消正在执行的策略"""
    result = StrategyService.cancel_executed_strategy(db, executed_id)
    if result:
        return {"success": True, "message": "策略已取消"}
    return {"success": False, "message": "策略取消失败"}

# 白名单API
@router.get("/whitelist")
def get_whitelist(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """获取白名单IP列表"""
    from app.models.strategy import WhitelistIP
    whitelist_ips = db.query(WhitelistIP).all()
    ips = [ip.ip_address for ip in whitelist_ips]
    return {"ips": ips}

@router.post("/whitelist/add")
async def add_whitelist_ip(
    request: Request,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """添加白名单IP"""
    from app.models.strategy import WhitelistIP
    from sqlalchemy.exc import IntegrityError
    
    try:
        body = await request.json()
        ip = body.get("ip")
        if not ip:
            return {"success": False, "message": "请提供IP地址"}
        
        new_ip = WhitelistIP(ip_address=ip)
        db.add(new_ip)
        db.commit()
        return {"success": True, "message": "IP添加成功"}
    except IntegrityError:
        db.rollback()
        return {"success": False, "message": "IP已存在"}
    except Exception as e:
        return {"success": False, "message": f"请求错误: {str(e)}"}

@router.post("/whitelist/remove")
async def remove_whitelist_ip(
    request: Request,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """删除白名单IP"""
    from app.models.strategy import WhitelistIP
    
    try:
        body = await request.json()
        ip = body.get("ip")
        if not ip:
            return {"success": False, "message": "请提供IP地址"}
        
        whitelist_ip = db.query(WhitelistIP).filter(WhitelistIP.ip_address == ip).first()
        if whitelist_ip:
            db.delete(whitelist_ip)
            db.commit()
            return {"success": True, "message": "IP删除成功"}
        return {"success": False, "message": "IP不存在"}
    except Exception as e:
        return {"success": False, "message": f"请求错误: {str(e)}"}
