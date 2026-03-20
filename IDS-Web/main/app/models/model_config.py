from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, Text, JSON
from sqlalchemy.sql import func
from app.core.database import Base

class ModelConfig(Base):
    __tablename__ = "model_configs"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    model_type = Column(String(50), nullable=False)  # cnn/binary/two_stage
    dataset_type = Column(String(50), nullable=False)  # cicids2017
    file_path = Column(String(500), nullable=False)
    is_active = Column(Boolean, default=False)
    accuracy = Column(Float, nullable=True)
    precision_score = Column(Float, nullable=True)
    recall_score = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    description = Column(Text, nullable=True)
    
    # 评估结果缓存（JSON格式存储完整评估结果）
    eval_results = Column(JSON, nullable=True)
    eval_results_binary = Column(JSON, nullable=True)  # 二分类评估结果（用于两阶段模型）
    eval_results_attack = Column(JSON, nullable=True)  # 六分类评估结果（用于两阶段模型）
    last_eval_time = Column(DateTime(timezone=True), nullable=True)
    
    # 二分类模型评估指标
    binary_accuracy = Column(Float, nullable=True)
    binary_precision = Column(Float, nullable=True)
    binary_recall = Column(Float, nullable=True)
    binary_f1 = Column(Float, nullable=True)
    
    # 训练历史数据（用于绘制训练曲线）
    train_loss_history = Column(JSON, nullable=True)
    val_loss_history = Column(JSON, nullable=True)
    train_acc_history = Column(JSON, nullable=True)
    val_acc_history = Column(JSON, nullable=True)
    
    # 两阶段模型的训练历史
    binary_train_loss_history = Column(JSON, nullable=True)
    binary_val_loss_history = Column(JSON, nullable=True)
    binary_train_acc_history = Column(JSON, nullable=True)
    binary_val_acc_history = Column(JSON, nullable=True)
    attack_train_loss_history = Column(JSON, nullable=True)
    attack_val_loss_history = Column(JSON, nullable=True)
    attack_train_acc_history = Column(JSON, nullable=True)
    attack_val_acc_history = Column(JSON, nullable=True)

class TrainingHistory(Base):
    __tablename__ = "training_history"
    
    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String(255))
    model_type = Column(String(50))
    dataset_type = Column(String(50))
    batch_size = Column(Integer)
    epochs = Column(Integer)
    learning_rate = Column(Float)
    hidden_dim = Column(Integer)
    num_layers = Column(Integer)
    use_cuda = Column(Boolean)
    status = Column(String(50))  # running/completed/failed
    progress = Column(Integer, default=0)  # 0-100
    loss = Column(Float, nullable=True)
    accuracy = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
