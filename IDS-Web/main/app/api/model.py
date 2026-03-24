from fastapi import APIRouter, Depends, UploadFile, File, Form, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
import os
import shutil
import pandas as pd
import numpy as np
from datetime import datetime

from app.core.database import get_db
from app.core.config import settings
from app.api.auth import get_current_user
from app.services.model_service import ModelService
from app.schemas.model import (
    ModelConfigCreate, ModelConfigResponse,
    TrainingParams, TrainingHistoryResponse, EvaluationResult
)
from app.models.model_config import ModelConfig, TrainingHistory

router = APIRouter()
model_service = ModelService()

@router.get("/list")
def get_model_list(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """获取模型列表"""
    configs = ModelService.get_model_configs(db)
    available_models = ModelService.get_available_models()
    
    return {
        "configs": configs,
        "available_models": available_models
    }

@router.delete("/delete/{model_id}")
def delete_model(
    model_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """删除模型"""
    success, message = ModelService.delete_model(db, model_id)
    return {"success": success, "message": message}

@router.post("/upload")
async def upload_model(
    file: UploadFile = File(...),
    name: str = Form(...),
    model_type: str = Form(...),
    dataset_type: str = Form(...),
    description: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """上传模型文件"""
    if not file.filename.endswith('.pth'):
        return {"success": False, "message": "请上传.pth模型文件"}
    
    # 保存模型文件
    model_dir = settings.MODEL_DIR
    os.makedirs(model_dir, exist_ok=True)
    file_path = os.path.join(model_dir, file.filename)
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    # 保存配置
    config_data = {
        "name": name,
        "model_type": model_type,
        "dataset_type": dataset_type,
        "file_path": file_path,
        "description": description,
        "is_active": False
    }
    
    db_config = ModelService.save_model_config(db, config_data)
    
    return {"success": True, "config": db_config}

@router.post("/set-active/{model_id}")
def set_active_model(
    model_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """设置当前使用的模型"""
    model = ModelService.set_active_model(db, model_id)
    if model:
        # 根据模型类型加载模型
        if model.model_type == "two_stage":
            # 加载两阶段模型
            binary_model_path = model.file_path
            # 构建攻击模型路径和scaler路径
            attack_model_path = binary_model_path.replace("two_stage_binary", "two_stage_attack")
            scaler_path = binary_model_path.replace("two_stage_binary", "scaler_two_stage").replace(".pth", ".pkl")
            
            # 根据数据集类型确定输入维度
            input_dim = 26  # 默认值
            if model.dataset_type == "cicids2017":
                input_dim = 26
            elif model.dataset_type == "custom":
                input_dim = 26  # 与cicids2017相同
            
            if os.path.exists(attack_model_path):
                success = model_service.load_two_stage_model(binary_model_path, attack_model_path, scaler_path, input_dim=input_dim)
                if success:
                    return {"success": True, "message": f"两阶段模型 {model.name} 已激活"}
                else:
                    return {"success": False, "message": "两阶段模型加载失败"}
            else:
                return {"success": False, "message": f"找不到六分类模型文件: {attack_model_path}"}
        elif model.model_type in ["binary", "CNN_2"]:
            # 加载二分类模型
            # 构建scaler路径（通过替换文件名和扩展名）
            scaler_path = model.file_path.replace("binary_", "scaler_binary_").replace(".pth", ".pkl")
            
            # 根据数据集类型确定输入维度
            input_dim = 26  # 默认值
            if model.dataset_type == "cicids2017":
                input_dim = 26
            elif model.dataset_type == "custom":
                input_dim = 26  # 与cicids2017相同
            
            success = model_service.load_model(model.file_path, model.model_type, input_dim=input_dim, scaler_path=scaler_path)
            if success:
                return {"success": True, "message": f"模型 {model.name} 已激活"}
            else:
                return {"success": False, "message": "模型加载失败"}
        elif model.model_type in ["cnn", "CNN_7"]:
            # 加载单阶段模型（七分类）
            # 根据数据集类型确定输入维度
            input_dim = 26  # 默认值
            if model.dataset_type == "cicids2017":
                input_dim = 26
            elif model.dataset_type == "custom":
                input_dim = 26  # 与cicids2017相同
            
            success = model_service.load_model(model.file_path, model.model_type, input_dim=input_dim)
            if success:
                return {"success": True, "message": f"模型 {model.name} 已激活"}
            else:
                return {"success": False, "message": "模型加载失败"}
        else:
            return {"success": False, "message": f"不支持的模型类型: {model.model_type}"}
    return {"success": False, "message": "模型设置失败"}

@router.get("/datasets")
def get_available_datasets(current_user = Depends(get_current_user)):
    """获取可用数据集"""
    base_path = "./data"
    
    datasets = {
        "cicids2017": {
            "path": os.path.join(base_path, "cicids2017", "CICIDS2017.csv"),
            "exists": os.path.exists(os.path.join(base_path, "cicids2017", "CICIDS2017.csv"))
        }
    }
    
    return datasets

@router.post("/upload-pcap-for-training")
async def upload_pcap_for_training(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    label: str = Form(...),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """上传PCAP文件用于训练"""
    try:
        print(f"Received file: {file.filename}")
        print(f"Received label: {label}")
        
        if not file.filename.endswith('.pcap'):
            print(f"File extension error: {file.filename}")
            return {"success": False, "message": "请上传PCAP文件"}
        
        # 保存上传的文件
        upload_dir = settings.UPLOAD_DIR
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, file.filename)
        
        print(f"Saving file to: {file_path}")
        
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        print(f"File saved successfully")
        
        # 后台处理PCAP文件
        background_tasks.add_task(process_pcap_for_training, file_path, label)
        
        return {"success": True, "message": "文件上传成功，正在处理中..."}
    except Exception as e:
        print(f"Error in upload_pcap_for_training: {e}")
        import traceback
        traceback.print_exc()
        return {"success": False, "message": f"上传失败: {str(e)}"}

@router.post("/train")
def start_training(
    params: TrainingParams,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """开始训练模型"""
    # 创建训练历史记录
    training_data = {
        "model_name": f"{params.model_type}_{params.dataset_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "model_type": params.model_type,
        "dataset_type": params.dataset_type,
        "batch_size": params.batch_size,
        "epochs": params.epochs,
        "learning_rate": params.learning_rate,
        "hidden_dim": params.hidden_dim,
        "num_layers": params.num_layers,
        "use_cuda": params.use_cuda,
        "status": "running",
        "progress": 0
    }
    
    history = ModelService.create_training_history(db, training_data)
    
    # 保存history_id，用于后续生成模型名称
    history_id_for_name = history.id
    
    # 后台训练
    background_tasks.add_task(train_model_task, history.id, params, db)
    
    return {"success": True, "history_id": history.id}

def process_pcap_for_training(file_path: str, label: str):
    """处理PCAP文件用于训练"""
    try:
        from scapy.all import rdpcap
        from app.services.capture_service import FlowManager
        
        # 读取PCAP文件
        packets = rdpcap(file_path)
        
        # 处理数据包并提取特征
        flow_manager = FlowManager()
        
        for packet in packets:
            flow_manager.process_packet(packet)
        
        # 清理过期的流，确保所有流都被收集到
        flow_manager.clean_expired_flows()
        
        flows = flow_manager.get_all_flows()
        
        # 准备特征数据
        features_list = []
        for flow in flows:
            features = flow.extract_features()
            if features:
                # 添加标签
                features['Label'] = label
                features_list.append(features)
        
        if not features_list:
            print(f"处理PCAP文件失败: 未提取到有效流量特征")
            return {"success": False, "message": "未提取到有效流量特征"}
        
        # 创建训练数据目录
        training_data_dir = os.path.join("./data", "custom")
        os.makedirs(training_data_dir, exist_ok=True)
        
        # 生成文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = os.path.basename(file_path).replace(".pcap", "")
        output_file = os.path.join(training_data_dir, f"{base_filename}_{label}_{timestamp}.csv")
        
        # 保存为CSV文件
        df = pd.DataFrame(features_list)
        df.to_csv(output_file, index=False)
        
        print(f"PCAP文件处理完成: {output_file}")
        print(f"共提取 {len(features_list)} 个流量流")
        
        return {"success": True, "message": f"处理完成，共提取 {len(features_list)} 个流量流", "file_path": output_file}
    
    except Exception as e:
        print(f"处理PCAP文件失败: {e}")
        import traceback
        traceback.print_exc()
        return {"success": False, "message": f"处理失败: {str(e)}"}

def train_model_task(history_id: int, params: TrainingParams, db: Session):
    """后台训练任务"""
    try:
        # 获取训练历史记录，获取model_name
        history = db.query(TrainingHistory).filter(TrainingHistory.id == history_id).first()
        model_name_from_history = history.model_name if history else f"{params.model_type}_{params.dataset_type}_{history_id}"
        
        # 从本地导入模型和工具
        from app.services.model_utils import get_dataset_loader, get_two_stage_dataset_loaders, train_model, train_two_stage_model
        from app.services.model_architectures import IDSConvNet, IDSBinaryClassifier, IDSAttackClassifier
        
        # 加载数据集
        base_data_path = './data'
        dataset_path = params.dataset_path or os.path.join(base_data_path, params.dataset_type)
        
        device = torch.device("cuda" if params.use_cuda and torch.cuda.is_available() else "cpu")
        
        # 根据模型类型选择训练方式
        # 注意：前端传递的是 CNN_7, CNN_2, two_stage
        if params.model_type == "two_stage":
            # 两阶段混合模型（先二分再六分）
            print("=" * 50)
            print("使用两阶段混合模型训练模式（先二分再六分）")
            print("=" * 50)
            
            # 加载两阶段数据集
            binary_train_loader, binary_test_loader, attack_train_loader, attack_test_loader, feature_dim, scaler = get_two_stage_dataset_loaders(
                params.dataset_type, dataset_path, params.batch_size
            )
            
            # 保存scaler
            scaler_save_path = os.path.join(settings.MODEL_DIR, 
                                           f"scaler_two_stage_{params.dataset_type}_{history_id}.pkl")
            import joblib
            joblib.dump(scaler, scaler_save_path)
            print(f"Scaler已保存到: {scaler_save_path}")
            
            # 初始化两阶段模型
            binary_model = IDSBinaryClassifier(input_dim=feature_dim)
            attack_model = IDSAttackClassifier(input_dim=feature_dim)
            
            # 训练两阶段模型 - 使用two_stage前缀命名
            binary_model_save_path = os.path.join(settings.MODEL_DIR, 
                                                   f"two_stage_binary_{params.dataset_type}_{history_id}.pth")
            attack_model_save_path = os.path.join(settings.MODEL_DIR, 
                                                  f"two_stage_attack_{params.dataset_type}_{history_id}.pth")
            
            # 定义进度回调函数
            def progress_callback(stage, current_epoch, total_epochs, progress_percent, loss, accuracy):
                """更新训练进度到数据库"""
                try:
                    ModelService.update_training_progress(
                        db, history_id, progress_percent, loss, accuracy
                    )
                    stage_name = "二分类" if stage == "binary" else "六分类"
                    print(f"{stage_name}训练进度更新: {progress_percent}% (Epoch {current_epoch}/{total_epochs})")
                except Exception as e:
                    print(f"更新进度失败: {e}")
            
            binary_model, attack_model, binary_history, attack_history = train_two_stage_model(
                binary_model=binary_model,
                attack_model=attack_model,
                binary_train_loader=binary_train_loader,
                binary_test_loader=binary_test_loader,
                attack_train_loader=attack_train_loader,
                attack_test_loader=attack_test_loader,
                n_epochs=params.epochs,
                learning_rate=params.learning_rate,
                device=device,
                patience=5,
                binary_model_save_path=binary_model_save_path,
                attack_model_save_path=attack_model_save_path,
                progress_callback=progress_callback
            )
            
            # 计算最终准确率（使用六分类的验证准确率）
            final_accuracy = attack_history['val_acc'][-1] if attack_history['val_acc'] else None
            
            # 更新训练历史为完成状态，进度100%
            ModelService.update_training_progress(db, history_id, 100, 
                                                 attack_history['val_loss'][-1] if attack_history['val_loss'] else None,
                                                 final_accuracy)
            ModelService.complete_training(db, history_id, "completed")
            
            # 训练成功后，自动创建模型配置记录
            try:
                model_config_data = {
                    "name": model_name_from_history,
                    "model_type": "two_stage",
                    "dataset_type": params.dataset_type,
                    "file_path": binary_model_save_path,  # 主路径保存二分类模型
                    "attack_model_path": attack_model_save_path,  # 六分类模型路径
                    "scaler_path": scaler_save_path,  # scaler路径
                    "description": f"两阶段混合模型训练完成于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    "is_active": False,
                    "accuracy": final_accuracy,
                    # 保存训练历史数据
                    "binary_train_loss_history": binary_history.get('train_loss', []),
                    "binary_val_loss_history": binary_history.get('val_loss', []),
                    "binary_train_acc_history": binary_history.get('train_acc', []),
                    "binary_val_acc_history": binary_history.get('val_acc', []),
                    "attack_train_loss_history": attack_history.get('train_loss', []),
                    "attack_val_loss_history": attack_history.get('val_loss', []),
                    "attack_train_acc_history": attack_history.get('train_acc', []),
                    "attack_val_acc_history": attack_history.get('val_acc', [])
                }
                ModelService.save_model_config(db, model_config_data)
                print(f"两阶段混合模型配置已创建: {model_config_data['name']}")
            except Exception as config_error:
                print(f"创建模型配置失败: {config_error}")
                import traceback
                traceback.print_exc()
            
            return
        
        elif params.model_type in ["binary", "CNN_2"]:
            # 单阶段（二分类）模型
            print("=" * 50)
            print("使用单阶段模型训练模式（二分类）")
            print("=" * 50)
            
            # 加载两阶段数据集（只使用二分类部分）
            binary_train_loader, binary_test_loader, _, _, feature_dim, scaler = get_two_stage_dataset_loaders(
                params.dataset_type, dataset_path, params.batch_size
            )
            
            # 保存scaler
            scaler_save_path = os.path.join(settings.MODEL_DIR, 
                                           f"scaler_binary_{params.dataset_type}_{history_id}.pkl")
            import joblib
            joblib.dump(scaler, scaler_save_path)
            print(f"Scaler已保存到: {scaler_save_path}")
            
            # 初始化二分类模型
            model = IDSBinaryClassifier(input_dim=feature_dim)
            model = model.to(device)
            
            # 训练模型
            model_save_path = os.path.join(settings.MODEL_DIR, 
                                           f"binary_{params.dataset_type}_{history_id}.pth")
            
            # 定义进度回调函数
            def binary_progress_callback(current_epoch, total_epochs, progress_percent, loss, accuracy):
                """更新训练进度到数据库"""
                try:
                    ModelService.update_training_progress(
                        db, history_id, progress_percent, loss, accuracy
                    )
                    print(f"训练进度更新: {progress_percent}% (Epoch {current_epoch}/{total_epochs})")
                except Exception as e:
                    print(f"更新进度失败: {e}")
            
            # 二分类不考虑样本不平衡，不设置类别权重
            
            model, history = train_model(
                model=model,
                train_loader=binary_train_loader,
                val_loader=binary_test_loader,
                n_epochs=params.epochs,
                learning_rate=params.learning_rate,
                device=device,
                patience=5,
                model_save_path=model_save_path,
                progress_callback=binary_progress_callback,
                use_focal_loss=False,  # 二分类不使用Focal Loss
                class_weights=None,    # 二分类不设置类别权重
                use_data_augmentation=False  # 二分类不使用数据增强
            )
            
            # 更新训练历史为完成状态，进度100%
            final_accuracy = history['val_acc'][-1] if history['val_acc'] else None
            ModelService.update_training_progress(db, history_id, 100, 
                                                 history['val_loss'][-1] if history['val_loss'] else None,
                                                 final_accuracy)
            ModelService.complete_training(db, history_id, "completed")
            
            # 训练成功后，自动创建模型配置记录
            try:
                model_config_data = {
                    "name": model_name_from_history,
                    "model_type": "CNN_2",  # 使用前端传递的类型
                    "dataset_type": params.dataset_type,
                    "file_path": model_save_path,
                    "scaler_path": scaler_save_path,  # scaler路径
                    "description": f"单阶段CNN（二分类）训练完成于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    "is_active": False,
                    "accuracy": final_accuracy,
                    # 保存训练历史数据
                    "train_loss_history": history.get('train_loss', []),
                    "val_loss_history": history.get('val_loss', []),
                    "train_acc_history": history.get('train_acc', []),
                    "val_acc_history": history.get('val_acc', [])
                }
                ModelService.save_model_config(db, model_config_data)
                print(f"CNN_2模型配置已创建: {model_config_data['name']}")
            except Exception as config_error:
                print(f"创建模型配置失败: {config_error}")
                import traceback
                traceback.print_exc()
            
            return
        
        elif params.model_type in ["cnn", "CNN_7"]:
            # 一阶段CNN（七分类）模型
            print("=" * 50)
            print("使用一阶段CNN模型训练模式（七分类）")
            print("=" * 50)
            
            train_loader, test_loader, feature_dim = get_dataset_loader(
                params.dataset_type, dataset_path, params.batch_size
            )
            
            # 初始化模型
            model = IDSConvNet(input_dim=feature_dim, num_classes=7)
            model = model.to(device)
            
            # 训练模型
            model_save_path = os.path.join(settings.MODEL_DIR, 
                                           f"cnn_{params.dataset_type}_{history_id}.pth")
            
            # 定义进度回调函数
            def single_stage_progress_callback(current_epoch, total_epochs, progress_percent, loss, accuracy):
                """更新训练进度到数据库"""
                try:
                    ModelService.update_training_progress(
                        db, history_id, progress_percent, loss, accuracy
                    )
                    print(f"训练进度更新: {progress_percent}% (Epoch {current_epoch}/{total_epochs})")
                except Exception as e:
                    print(f"更新进度失败: {e}")
            
            # 计算类别权重，处理样本不平衡问题
            class_counts = [22731, 1966, 2767, 19035, 36, 7946, 2180]
            total_samples = sum(class_counts)
            class_weights = [total_samples / count for count in class_counts]
            
            model, history = train_model(
                model=model,
                train_loader=train_loader,
                val_loader=test_loader,
                n_epochs=params.epochs,
                learning_rate=params.learning_rate,
                device=device,
                patience=5,
                model_save_path=model_save_path,
                progress_callback=single_stage_progress_callback,
                use_focal_loss=True,
                class_weights=class_weights,
                use_data_augmentation=True
            )
            
            # 更新训练历史为完成状态，进度100%
            final_accuracy = history['val_acc'][-1] if history['val_acc'] else None
            ModelService.update_training_progress(db, history_id, 100, 
                                                 history['val_loss'][-1] if history['val_loss'] else None,
                                                 final_accuracy)
            ModelService.complete_training(db, history_id, "completed")
            
            # 训练成功后，自动创建模型配置记录
            try:
                model_config_data = {
                    "name": model_name_from_history,
                    "model_type": "CNN_7",  # 使用前端传递的类型
                    "dataset_type": params.dataset_type,
                    "file_path": model_save_path,
                    "description": f"单阶段CNN（七分类）训练完成于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    "is_active": False,
                    "accuracy": final_accuracy,
                    # 保存训练历史数据
                    "train_loss_history": history.get('train_loss', []),
                    "val_loss_history": history.get('val_loss', []),
                    "train_acc_history": history.get('train_acc', []),
                    "val_acc_history": history.get('val_acc', [])
                }
                ModelService.save_model_config(db, model_config_data)
                print(f"CNN_7模型配置已创建: {model_config_data['name']}")
            except Exception as config_error:
                print(f"创建模型配置失败: {config_error}")
                import traceback
                traceback.print_exc()
        
        else:
            # 未知的模型类型
            print(f"错误: 未知的模型类型 '{params.model_type}'")
            ModelService.complete_training(db, history_id, "failed")
            return {"success": False, "message": f"未知的模型类型: {params.model_type}"}
        
    except Exception as e:
        print(f"训练失败: {e}")
        import traceback
        traceback.print_exc()
        ModelService.complete_training(db, history_id, "failed")

@router.get("/training-history")
def get_training_history(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """获取训练历史"""
    history = ModelService.get_training_history(db, skip, limit)
    return history

@router.delete("/training-history")
def clear_training_history(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """清空训练历史"""
    try:
        from app.models.model_config import TrainingHistory
        db.query(TrainingHistory).delete()
        db.commit()
        return {"success": True, "message": "训练历史已清空"}
    except Exception as e:
        db.rollback()
        return {"success": False, "message": f"清空训练历史失败: {str(e)}"}

@router.post("/evaluate/{model_id}")
def evaluate_model(
    model_id: int,
    force_reeval: bool = False,  # 是否强制重新评估
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """评估模型
    
    参数:
        model_id: 模型ID
        force_reeval: 是否强制重新评估，默认为False，如果有缓存结果则直接返回
    """
    from datetime import datetime
    
    model = db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
    if not model:
        return {"success": False, "message": "模型不存在"}
    
    # 检查是否有缓存的评估结果
    if not force_reeval and model.eval_results is not None:
        result = {
            "success": True,
            "message": "使用缓存的评估结果",
            "model_type": model.model_type,
            "from_cache": True,
            "last_eval_time": model.last_eval_time.isoformat() if model.last_eval_time else None,
            **model.eval_results
        }
        # 添加训练历史数据
        if model.model_type == "two_stage":
            # 两阶段模型使用专用的训练历史字段
            if model.binary_train_loss_history:
                result["train_loss_history"] = model.binary_train_loss_history
            if model.binary_val_loss_history:
                result["val_loss_history"] = model.binary_val_loss_history
            if model.binary_train_acc_history:
                result["train_acc_history"] = model.binary_train_acc_history
            if model.binary_val_acc_history:
                result["val_acc_history"] = model.binary_val_acc_history
        else:
            # 其他模型使用通用训练历史字段
            if model.train_loss_history:
                result["train_loss_history"] = model.train_loss_history
            if model.val_loss_history:
                result["val_loss_history"] = model.val_loss_history
            if model.train_acc_history:
                result["train_acc_history"] = model.train_acc_history
            if model.val_acc_history:
                result["val_acc_history"] = model.val_acc_history
        return result
    
    # 确定测试数据路径
    base_path = "./data"
    test_data_path = os.path.join(base_path, "cicids2017")
    
    # 根据模型类型进行不同评估
    if model.model_type == "two_stage":
        # 两阶段模型需要评估两个子模型
        result = model_service.evaluate_two_stage_model(
            model.file_path, test_data_path, model.dataset_type
        )
    elif model.model_type in ["binary", "CNN_2"]:
        # 二分类模型评估
        result = model_service.evaluate_binary_model(model.file_path, test_data_path)
    elif model.model_type in ["cnn", "CNN_7"]:
        # 七分类模型评估
        result = model_service.evaluate_model(model.file_path, test_data_path, model.model_type)
    else:
        return {"error": f"不支持的模型类型: {model.model_type}"}
    
    if "error" not in result:
        # 更新模型评估指标
        if model.model_type in ["binary", "CNN_2"]:
            model.binary_accuracy = result.get("accuracy")
            model.binary_precision = result.get("precision")
            model.binary_recall = result.get("recall")
            model.binary_f1 = result.get("f1_score")
        else:
            model.accuracy = result.get("accuracy")
            model.precision_score = result.get("precision")
            model.recall_score = result.get("recall")
            model.f1_score = result.get("f1_score")
        
        # 保存评估结果到缓存
        model.eval_results = result
        model.last_eval_time = datetime.now()
        
        # 如果是两阶段模型，保存两个子模型的结果
        if model.model_type == "two_stage":
            model.eval_results_binary = result.get("binary_results")
            model.eval_results_attack = result.get("attack_results")
        
        db.commit()
    
    # 添加训练历史数据到返回结果
    if model.model_type == "two_stage":
        # 两阶段模型使用专用的训练历史字段
        if model.binary_train_loss_history:
            result["binary_train_loss_history"] = model.binary_train_loss_history
        if model.binary_val_loss_history:
            result["binary_val_loss_history"] = model.binary_val_loss_history
        if model.binary_train_acc_history:
            result["binary_train_acc_history"] = model.binary_train_acc_history
        if model.binary_val_acc_history:
            result["binary_val_acc_history"] = model.binary_val_acc_history
        # 添加六分类模型的训练历史数据
        if model.attack_train_loss_history:
            result["attack_train_loss_history"] = model.attack_train_loss_history
        if model.attack_val_loss_history:
            result["attack_val_loss_history"] = model.attack_val_loss_history
        if model.attack_train_acc_history:
            result["attack_train_acc_history"] = model.attack_train_acc_history
        if model.attack_val_acc_history:
            result["attack_val_acc_history"] = model.attack_val_acc_history
    else:
        # 其他模型使用通用训练历史字段
        if model.train_loss_history:
            result["train_loss_history"] = model.train_loss_history
        if model.val_loss_history:
            result["val_loss_history"] = model.val_loss_history
        if model.train_acc_history:
            result["train_acc_history"] = model.train_acc_history
        if model.val_acc_history:
            result["val_acc_history"] = model.val_acc_history
    
    return result


@router.get("/evaluate/{model_id}")
def get_evaluation_result(
    model_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """获取模型评估结果（不重新评估，只返回缓存结果）"""
    model = db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
    if not model:
        return {"success": False, "message": "模型不存在"}
    
    if model.eval_results is None:
        return {"success": False, "message": "该模型尚未进行评估", "need_eval": True}
    
    result = {
        "success": True,
        "model_type": model.model_type,
        "from_cache": True,
        "last_eval_time": model.last_eval_time.isoformat() if model.last_eval_time else None,
        **model.eval_results
    }
    
    # 添加训练历史数据
    if model.model_type == "two_stage":
        # 两阶段模型使用专用的训练历史字段
        if model.binary_train_loss_history:
            result["train_loss_history"] = model.binary_train_loss_history
        if model.binary_val_loss_history:
            result["val_loss_history"] = model.binary_val_loss_history
        if model.binary_train_acc_history:
            result["train_acc_history"] = model.binary_train_acc_history
        if model.binary_val_acc_history:
            result["val_acc_history"] = model.binary_val_acc_history
    else:
        # 其他模型使用通用训练历史字段
        if model.train_loss_history:
            result["train_loss_history"] = model.train_loss_history
        if model.val_loss_history:
            result["val_loss_history"] = model.val_loss_history
        if model.train_acc_history:
            result["train_acc_history"] = model.train_acc_history
        if model.val_acc_history:
            result["val_acc_history"] = model.val_acc_history
    
    return result

from datetime import datetime
import torch
