from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

class ModelConfigCreate(BaseModel):
    name: str
    model_type: str  # cnn
    dataset_type: str  # cicids2017
    file_path: str
    description: Optional[str] = None
    
    class Config:
        protected_namespaces = ()

class ModelConfigResponse(BaseModel):
    id: int
    name: str
    model_type: str
    dataset_type: str
    file_path: str
    is_active: bool
    accuracy: Optional[float] = None
    precision_score: Optional[float] = None
    recall_score: Optional[float] = None
    f1_score: Optional[float] = None
    created_at: datetime
    description: Optional[str] = None
    
    class Config:
        from_attributes = True
        protected_namespaces = ()

class TrainingParams(BaseModel):
    model_type: str  # cnn/two_stage
    dataset_type: str  # cicids2017
    dataset_path: Optional[str] = None
    batch_size: int = 64
    epochs: int = 30
    learning_rate: float = 0.001
    hidden_dim: int = 128
    num_layers: int = 2
    dropout: float = 0.5
    use_cuda: bool = True
    use_two_stage: bool = False  # 是否使用两阶段训练
    
    class Config:
        protected_namespaces = ()

class TrainingHistoryResponse(BaseModel):
    id: int
    model_name: str
    model_type: str
    dataset_type: str
    batch_size: int
    epochs: int
    learning_rate: float
    hidden_dim: int
    num_layers: int
    use_cuda: bool
    status: str
    progress: int
    loss: Optional[float] = None
    accuracy: Optional[float] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True
        protected_namespaces = ()

class EvaluationResult(BaseModel):
    model_id: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    confusion_matrix: List[List[int]]
    roc_auc: Optional[float] = None
    avg_precision: Optional[float] = None
    
    class Config:
        protected_namespaces = ()
