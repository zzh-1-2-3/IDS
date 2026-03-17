from fastapi import APIRouter
from app.api import auth, dashboard, traffic, detection, strategy, model

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["认证"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["仪表盘"])
api_router.include_router(traffic.router, prefix="/traffic", tags=["网络流量"])
api_router.include_router(detection.router, prefix="/detection", tags=["检测结果"])
api_router.include_router(strategy.router, prefix="/strategy", tags=["响应策略"])
api_router.include_router(model.router, prefix="/model", tags=["模型管理"])
