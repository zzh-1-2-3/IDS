from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    # 应用配置
    APP_NAME: str = "IDS入侵检测系统"
    DEBUG: bool = True
    VERSION: str = "1.0.0"
    
    # 数据库配置
    DB_HOST: str = "localhost"
    DB_PORT: int = 3306
    DB_USER: str = "root"
    DB_PASSWORD: str = "******"
    DB_NAME: str = "IDS"
    
    # JWT配置
    SECRET_KEY: str = "ids-secret-key-2024"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24小时
    
    # 模型配置
    MODEL_DIR: str = "./saved_models"
    UPLOAD_DIR: str = "./uploads"
    
    # 检测配置
    ATTACK_TYPES: list = [
        "BENIGN", "Bot", "BruteForce", "DoS", 
        "Infiltration", "PortScan", "WebAttack"
    ]
    
    # 威胁级别映射
    THREAT_LEVELS: dict = {
        "BENIGN": "low",
        "Bot": "medium",
        "BruteForce": "high",
        "DoS": "high",
        "Infiltration": "high",
        "PortScan": "medium",
        "WebAttack": "high"
    }
    
    class Config:
        env_file = ".env"

settings = Settings()
