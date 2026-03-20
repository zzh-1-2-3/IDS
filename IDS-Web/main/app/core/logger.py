import os
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler

# 日志目录
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# 定义不同的日志文件
LOG_FILES = {
    'capture': os.path.join(LOG_DIR, 'capture.log'),      # 流量捕获日志
    'detection': os.path.join(LOG_DIR, 'detection.log'),  # 检测日志
    'strategy': os.path.join(LOG_DIR, 'strategy.log'),    # 策略匹配日志
    'training': os.path.join(LOG_DIR, 'training.log'),    # 模型训练日志
}

class LoggerManager:
    """日志管理器 - 将不同类型的日志分别写入不同的文件"""
    
    _loggers = {}
    
    @staticmethod
    def get_logger(name: str, log_file: str = None):
        """获取或创建日志记录器
        
        Args:
            name: 日志记录器名称
            log_file: 日志文件路径，如果为None则使用控制台输出
        
        Returns:
            logging.Logger: 日志记录器
        """
        if name in LoggerManager._loggers:
            return LoggerManager._loggers[name]
        
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        
        # 清除现有的处理器
        logger.handlers = []
        
        if log_file:
            # 创建文件处理器
            handler = RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        LoggerManager._loggers[name] = logger
        return logger
    
    @staticmethod
    def capture_log(message: str):
        """记录流量捕获日志"""
        logger = LoggerManager.get_logger('capture', LOG_FILES['capture'])
        logger.info(message)
    
    @staticmethod
    def detection_log(message: str):
        """记录检测日志"""
        logger = LoggerManager.get_logger('detection', LOG_FILES['detection'])
        logger.info(message)
    
    @staticmethod
    def strategy_log(message: str):
        """记录策略匹配日志"""
        logger = LoggerManager.get_logger('strategy', LOG_FILES['strategy'])
        logger.info(message)
    
    @staticmethod
    def training_log(message: str):
        """记录模型训练日志"""
        logger = LoggerManager.get_logger('training', LOG_FILES['training'])
        logger.info(message)

# 便捷函数
def log_capture(message: str):
    """记录流量捕获日志"""
    LoggerManager.capture_log(message)

def log_detection(message: str):
    """记录检测日志"""
    LoggerManager.detection_log(message)

def log_strategy(message: str):
    """记录策略匹配日志"""
    LoggerManager.strategy_log(message)

def log_training(message: str):
    """记录模型训练日志"""
    LoggerManager.training_log(message)
