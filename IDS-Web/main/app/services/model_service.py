import os
import torch
import torch.nn as nn
import numpy as np
import pandas as pd
import joblib
from sqlalchemy.orm import Session
from typing import List, Optional, Tuple
import json

from app.models.model_config import ModelConfig, TrainingHistory
from app.core.config import settings
from app.services.threat_scorer import evaluate_threat

# 导入模型定义
from app.services.model_architectures import IDSConvNet, IDSBinaryClassifier, IDSAttackClassifier
from app.services.model_utils import load_cicids2017

class ModelService:
    _instance = None
    _current_model = None
    _current_model_config = None
    _device = None
    _scaler = None
    
    # 两阶段模型
    _binary_model = None
    _attack_model = None
    
    # 攻击类型映射（多分类）
    ATTACK_TYPES = ["BENIGN", "Bot", "BruteForce", "DoS", "Infiltration", "PortScan", "WebAttack"]
    
    # 攻击类型映射（六分类，用于第二阶段）
    ATTACK_TYPES_SIX = ["Bot", "BruteForce", "DoS", "Infiltration", "PortScan", "WebAttack"]
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ModelService, cls).__new__(cls)
            cls._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        return cls._instance
    
    @staticmethod
    def reset_all_model_status(db: Session):
        """重置所有模型的使用状态为未使用（服务启动时调用）"""
        db.query(ModelConfig).update({"is_active": False})
        db.commit()
        print("已重置所有模型状态为未使用")
    
    @staticmethod
    def initialize_models_from_directory(db: Session):
        """从模型目录初始化模型到数据库
        当系统部署到新环境时，扫描saved_models文件夹中的模型文件并添加到数据库
        """
        model_dir = settings.MODEL_DIR
        if not os.path.exists(model_dir):
            print(f"模型目录不存在: {model_dir}")
            return
        
        # 获取数据库中已有的模型路径
        existing_models = db.query(ModelConfig).all()
        existing_paths = {model.file_path for model in existing_models if model.file_path}
        
        # 扫描模型文件
        for file in os.listdir(model_dir):
            if file.endswith('.pth'):
                file_path = os.path.join(model_dir, file)
                
                # 跳过已存在的模型
                if file_path in existing_paths:
                    continue
                
                # 分析模型类型 - 新的命名规则
                model_type = "cnn"  # 默认类型
                
                # 两阶段模型: two_stage_binary_xxx.pth 或 two_stage_attack_xxx.pth
                if file.lower().startswith("two_stage_binary"):
                    model_type = "two_stage"
                    # 检查对应的attack模型是否存在
                    attack_file = file.replace("two_stage_binary", "two_stage_attack")
                    attack_path = os.path.join(model_dir, attack_file)
                    if not os.path.exists(attack_path):
                        print(f"警告: 两阶段模型缺少attack文件: {attack_file}")
                elif file.lower().startswith("two_stage_attack"):
                    # attack模型是两阶段模型的一部分，跳过单独处理
                    continue
                # 单阶段二分类模型: binary_xxx.pth
                elif file.lower().startswith("binary_"):
                    model_type = "CNN_2"
                # 单阶段七分类模型: cnn_xxx.pth
                elif file.lower().startswith("cnn_"):
                    model_type = "CNN_7"
                
                # 分析数据集类型
                dataset_type = "cicids2017"  # 默认数据集
                if "custom" in file.lower():
                    dataset_type = "custom"
                
                # 创建模型名称
                model_name = file.replace('.pth', '')
                
                # 创建模型配置
                config_data = {
                    "name": model_name,
                    "model_type": model_type,
                    "dataset_type": dataset_type,
                    "file_path": file_path,
                    "description": f"从目录初始化的模型: {file}",
                    "is_active": False
                }
                
                # 保存到数据库
                try:
                    ModelService.save_model_config(db, config_data)
                    print(f"已初始化模型: {model_name} (类型: {model_type})")
                except Exception as e:
                    print(f"初始化模型失败 {file}: {e}")
        
        print("模型目录初始化完成")
    
    @staticmethod
    def get_available_models() -> List[dict]:
        """获取所有可用的模型文件"""
        model_dir = settings.MODEL_DIR
        models = []
        
        if os.path.exists(model_dir):
            for file in os.listdir(model_dir):
                if file.endswith('.pth'):
                    models.append({
                        "name": file,
                        "path": os.path.join(model_dir, file),
                        "size": os.path.getsize(os.path.join(model_dir, file))
                    })
        
        return models
    
    @staticmethod
    def delete_model(db: Session, model_id: int):
        """删除模型"""
        try:
            # 获取模型配置
            model_config = db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
            if not model_config:
                return False, "模型不存在"
            
            # 获取模型名称（用于删除eval_results中的图表）
            model_name = os.path.basename(model_config.file_path).replace('.pth', '') if model_config.file_path else None
            
            # 删除模型文件（使用file_path字段）
            if model_config.file_path and os.path.exists(model_config.file_path):
                os.remove(model_config.file_path)
                print(f"删除模型文件: {model_config.file_path}")
            
            # 如果是两阶段模型，删除两个模型文件
            if model_config.model_type == "two_stage":
                # 两阶段模型的file_path指向二分类模型，六分类模型路径通过替换名称得到
                binary_model_path = model_config.file_path
                
                # 构建attack模型路径和scaler路径
                attack_model_path = binary_model_path.replace("two_stage_binary", "two_stage_attack")
                scaler_path = binary_model_path.replace("two_stage_binary", "scaler_two_stage").replace(".pth", ".pkl")
                
                if os.path.exists(binary_model_path):
                    os.remove(binary_model_path)
                    print(f"删除二分类模型文件: {binary_model_path}")
                if os.path.exists(attack_model_path):
                    os.remove(attack_model_path)
                    print(f"删除六分类模型文件: {attack_model_path}")
                
                # 删除两阶段模型的scaler文件
                if os.path.exists(scaler_path):
                    os.remove(scaler_path)
                    print(f"删除scaler文件: {scaler_path}")
            else:
                # 删除单阶段模型的scaler文件
                scaler_path = model_config.file_path.replace(".pth", "_scaler.pkl")
                if os.path.exists(scaler_path):
                    os.remove(scaler_path)
                    print(f"删除scaler文件: {scaler_path}")
            
            # 删除eval_results中的评估图表
            if model_name:
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
                eval_dir = os.path.join(base_dir, 'eval_results')
                
                if os.path.exists(eval_dir):
                    # 删除与该模型相关的所有图表文件
                    for file in os.listdir(eval_dir):
                        if file.startswith(model_name):
                            file_path = os.path.join(eval_dir, file)
                            try:
                                os.remove(file_path)
                                print(f"删除评估图表: {file_path}")
                            except Exception as e:
                                print(f"删除评估图表失败 {file}: {e}")
                    
                    # 对于两阶段模型，还需要删除attack相关的图表
                    if model_config.model_type == "two_stage":
                        # 构建attack模型名称
                        attack_model_name = model_name.replace("two_stage_binary", "two_stage_attack")
                        
                        for file in os.listdir(eval_dir):
                            if file.startswith(attack_model_name):
                                file_path = os.path.join(eval_dir, file)
                                try:
                                    os.remove(file_path)
                                    print(f"删除评估图表: {file_path}")
                                except Exception as e:
                                    print(f"删除评估图表失败 {file}: {e}")
            
            # 删除数据库记录
            db.delete(model_config)
            db.commit()
            return True, "模型删除成功"
        except Exception as e:
            print(f"删除模型失败: {e}")
            db.rollback()
            return False, f"删除失败: {str(e)}"
    
    def load_model(self, model_path: str, model_type: str = "cnn", input_dim: int = 28, scaler_path: str = None):
        """加载模型"""
        try:
            # 直接使用导入的模型类
            # 支持多种模型类型标识
            if model_type in ["cnn", "CNN_7"]:
                # 一阶段CNN（七分类）
                model = IDSConvNet(input_dim=input_dim, num_classes=len(self.ATTACK_TYPES))
            elif model_type in ["binary", "CNN_2"]:
                # 二分类模型
                model = IDSBinaryClassifier(input_dim=input_dim)
            else:
                raise ValueError(f"不支持的模型类型: {model_type}")
            
            # 加载权重
            if os.path.exists(model_path):
                state_dict = torch.load(model_path, map_location=self._device)
                model.load_state_dict(state_dict)
                model.to(self._device)
                model.eval()
                self._current_model = model
                
                # 加载scaler
                if scaler_path and os.path.exists(scaler_path):
                    self._scaler = joblib.load(scaler_path)
                    print(f"Scaler已加载: {scaler_path}")
                else:
                    self._scaler = None
                    print("警告: 未找到scaler文件")
                
                # 清除两阶段模型状态
                self._binary_model = None
                self._attack_model = None
                return True
            return False
        except Exception as e:
            print(f"加载模型失败: {e}")
            return False
    
    def load_two_stage_model(self, binary_model_path: str, attack_model_path: str, scaler_path: str = None, input_dim: int = 28):
        """加载两阶段模型"""
        try:
            # 加载二分类模型
            binary_model = IDSBinaryClassifier(input_dim=input_dim)
            if os.path.exists(binary_model_path):
                state_dict = torch.load(binary_model_path, map_location=self._device)
                binary_model.load_state_dict(state_dict)
                binary_model.to(self._device)
                binary_model.eval()
                self._binary_model = binary_model
            else:
                return False
            
            # 加载六分类模型
            attack_model = IDSAttackClassifier(input_dim=input_dim)
            if os.path.exists(attack_model_path):
                state_dict = torch.load(attack_model_path, map_location=self._device)
                attack_model.load_state_dict(state_dict)
                attack_model.to(self._device)
                attack_model.eval()
                self._attack_model = attack_model
            else:
                return False
            
            # 加载scaler
            if scaler_path and os.path.exists(scaler_path):
                self._scaler = joblib.load(scaler_path)
                print(f"Scaler已加载: {scaler_path}")
            else:
                self._scaler = None
                print("警告: 未找到scaler文件")
            
            # 清除单阶段模型状态
            self._current_model = None
            
            return True
        except Exception as e:
            print(f"加载两阶段模型失败: {e}")
            return False
    
    def predict_two_stage(self, features: np.ndarray) -> Tuple[str, float, str]:
        """
        两阶段预测
        返回: (攻击类型, 置信度, 威胁级别)
        """
        if self._binary_model is None or self._attack_model is None:
            return "Unknown", 0.0, "low"
        
        try:
            # 数据类型检查和转换
            features = np.array(features, dtype=np.float32)
            
            # 处理无穷大和NaN值
            features = np.nan_to_num(features, nan=0.0, posinf=1e10, neginf=-1e10)
            
            # 数据预处理 - 使用训练时保存的scaler
            if self._scaler is not None:
                features = self._scaler.transform(features.reshape(1, -1))
            
            # 转换为tensor
            input_tensor = torch.FloatTensor(features).to(self._device)
            if len(input_tensor.shape) == 1:
                input_tensor = input_tensor.unsqueeze(0)
            
            # 第一阶段：二分类
            with torch.no_grad():
                binary_output = self._binary_model(input_tensor)
                
                # 直接使用softmax输出，与参考项目一致
                binary_prob = torch.softmax(binary_output, dim=1)
                
                # 获取预测结果
                confidence, predicted = torch.max(binary_prob, 1)
                
                # 0 = BENIGN, 1 = Attack
                if predicted.item() == 0:
                    confidence_val = confidence.item()
                    score, threat_level, level_chinese = evaluate_threat("BENIGN", confidence_val)
                    return "BENIGN", confidence_val, threat_level
                
                # 第二阶段：六分类
                attack_output = self._attack_model(input_tensor)
                attack_prob = torch.softmax(attack_output, dim=1)
                confidence, predicted = torch.max(attack_prob, 1)
                
                attack_type = self.ATTACK_TYPES_SIX[predicted.item()]
                confidence_val = confidence.item()
                
                # 使用威胁等级计算模块
                score, threat_level, level_chinese = evaluate_threat(attack_type, confidence_val)
                
                return attack_type, confidence_val, threat_level
        except Exception as e:
            print(f"两阶段预测失败: {e}")
            return "Unknown", 0.0, "low"
    
    def predict(self, features: np.ndarray) -> Tuple[str, float, str]:
        """
        预测攻击类型
        返回: (攻击类型, 置信度, 威胁级别)
        """
        # 如果加载了两阶段模型，使用两阶段预测
        if self._binary_model is not None and self._attack_model is not None:
            return self.predict_two_stage(features)
        
        # 否则使用单阶段预测
        if self._current_model is None:
            return "Unknown", 0.0, "low"
        
        try:
            # 数据类型检查和转换
            features = np.array(features, dtype=np.float32)
            
            # 处理无穷大和NaN值
            features = np.nan_to_num(features, nan=0.0, posinf=1e10, neginf=-1e10)
            
            # 数据预处理
            if self._scaler is not None:
                features = self._scaler.transform(features.reshape(1, -1))
            
            # 转换为tensor
            input_tensor = torch.FloatTensor(features).to(self._device)
            if len(input_tensor.shape) == 1:
                input_tensor = input_tensor.unsqueeze(0)
            
            # 预测
            with torch.no_grad():
                outputs = self._current_model(input_tensor)
                probabilities = torch.softmax(outputs, dim=1)
                confidence, predicted = torch.max(probabilities, 1)
            
            attack_type = self.ATTACK_TYPES[predicted.item()]
            confidence_val = confidence.item()
            
            # 使用威胁等级计算模块
            score, threat_level, level_chinese = evaluate_threat(attack_type, confidence_val)
            
            return attack_type, confidence_val, threat_level
        except Exception as e:
            print(f"预测失败: {e}")
            return "Unknown", 0.0, "low"
    
    def predict_batch(self, features_list: List[np.ndarray]) -> List[Tuple[str, float, str]]:
        """批量预测"""
        results = []
        for features in features_list:
            result = self.predict(features)
            results.append(result)
        return results
    
    @staticmethod
    def save_model_config(db: Session, config_data: dict) -> ModelConfig:
        """保存模型配置"""
        # 如果设置为激活，取消其他模型的激活状态
        if config_data.get("is_active"):
            db.query(ModelConfig).update({"is_active": False})
        
        # 过滤掉 ModelConfig 类中不存在的字段
        model_config_fields = {
            "id", "name", "model_type", "dataset_type", "file_path", "is_active",
            "accuracy", "precision_score", "recall_score", "f1_score", "created_at",
            "description", "eval_results", "eval_results_binary", "eval_results_attack",
            "last_eval_time", "binary_accuracy", "binary_precision", "binary_recall",
            "binary_f1", "train_loss_history", "val_loss_history", "train_acc_history",
            "val_acc_history", "binary_train_loss_history", "binary_val_loss_history",
            "binary_train_acc_history", "binary_val_acc_history", "attack_train_loss_history",
            "attack_val_loss_history", "attack_train_acc_history", "attack_val_acc_history"
        }
        
        filtered_config_data = {k: v for k, v in config_data.items() if k in model_config_fields}
        
        db_config = ModelConfig(**filtered_config_data)
        db.add(db_config)
        db.commit()
        db.refresh(db_config)
        return db_config
    
    @staticmethod
    def get_model_configs(db: Session, skip: int = 0, limit: int = 100):
        """获取所有模型配置，过滤掉文件不存在的记录"""
        configs = db.query(ModelConfig).offset(skip).limit(limit).all()
        
        # 过滤掉文件不存在的配置
        valid_configs = []
        for config in configs:
            if os.path.exists(config.file_path):
                valid_configs.append(config)
            else:
                # 可选：自动删除文件不存在的配置
                # db.delete(config)
                # db.commit()
                pass
        
        return valid_configs
    
    @staticmethod
    def set_active_model(db: Session, model_id: int):
        """设置当前使用的模型"""
        # 取消所有激活状态
        db.query(ModelConfig).update({"is_active": False})
        
        # 设置指定模型为激活
        model = db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
        if model:
            model.is_active = True
            db.commit()
            db.refresh(model)
        return model
    
    @staticmethod
    def create_training_history(db: Session, training_data: dict) -> TrainingHistory:
        """创建训练历史记录"""
        db_history = TrainingHistory(**training_data)
        db.add(db_history)
        db.commit()
        db.refresh(db_history)
        return db_history
    
    @staticmethod
    def update_training_progress(db: Session, history_id: int, progress: int, loss: float = None, accuracy: float = None):
        """更新训练进度"""
        history = db.query(TrainingHistory).filter(TrainingHistory.id == history_id).first()
        if history:
            history.progress = progress
            if loss is not None:
                history.loss = loss
            if accuracy is not None:
                history.accuracy = accuracy
            db.commit()
            db.refresh(history)
        return history
    
    @staticmethod
    def complete_training(db: Session, history_id: int, status: str = "completed"):
        """完成训练"""
        from datetime import datetime
        history = db.query(TrainingHistory).filter(TrainingHistory.id == history_id).first()
        if history:
            history.status = status
            history.completed_at = datetime.now()
            db.commit()
            db.refresh(history)
        return history
    
    @staticmethod
    def get_training_history(db: Session, skip: int = 0, limit: int = 100):
        """获取训练历史"""
        return db.query(TrainingHistory).order_by(TrainingHistory.created_at.desc()).offset(skip).limit(limit).all()
    
    def evaluate_model(self, model_path: str, test_data_path: str, model_type: str = "cnn") -> dict:
        """评估模型 """
        try:
            import matplotlib
            matplotlib.use('Agg')  # 使用非交互式后端
            import matplotlib.pyplot as plt
            import seaborn as sns
            
            # 设置中文字体
            plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'Arial Unicode MS', 'DejaVu Sans']
            plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题
            
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
            from sklearn.metrics import roc_curve, auc, precision_recall_curve
            from sklearn.preprocessing import label_binarize
            
            # 加载测试数据
            X_train, X_test, y_train, y_test, _ = load_cicids2017(test_data_path)
            
            # 加载模型
            input_dim = X_test.shape[1]
            if not self.load_model(model_path, model_type, input_dim=input_dim):
                return {"error": "模型加载失败"}
            
            # 评估
            self._current_model.eval()
            y_true = []
            y_pred = []
            y_score = []  # 用于ROC曲线
            
            X_test_tensor = torch.FloatTensor(X_test).to(self._device)
            y_test_tensor = torch.LongTensor(y_test.values if hasattr(y_test, 'values') else y_test)
            
            batch_size = 64
            with torch.no_grad():
                for i in range(0, len(X_test_tensor), batch_size):
                    batch = X_test_tensor[i:i+batch_size]
                    outputs = self._current_model(batch)
                    _, predicted = torch.max(outputs, 1)
                    # 获取概率分数用于ROC曲线
                    scores = torch.softmax(outputs, dim=1).cpu().numpy()
                    y_pred.extend(predicted.cpu().numpy())
                    y_true.extend(y_test_tensor[i:i+batch_size].cpu().numpy())
                    y_score.extend(scores)
            
            y_true = np.array(y_true)
            y_pred = np.array(y_pred)
            y_score = np.array(y_score)
            
            # 计算指标 - 多分类评估
            accuracy = accuracy_score(y_true, y_pred)
            precision = precision_score(y_true, y_pred, average='weighted', zero_division=0)
            recall = recall_score(y_true, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)
            cm = confusion_matrix(y_true, y_pred)
            
            # 生成图表保存路径
            from app.core.config import settings
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            eval_dir = os.path.join(base_dir, 'eval_results')
            os.makedirs(eval_dir, exist_ok=True)
            model_name = os.path.basename(model_path).replace('.pth', '')
            
            # 绘制混淆矩阵
            cm_path = os.path.join(eval_dir, f"{model_name}_confusion_matrix.png")
            plt.figure(figsize=(10, 8))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False,
                       xticklabels=self.ATTACK_TYPES,
                       yticklabels=self.ATTACK_TYPES)
            plt.xlabel('预测标签')
            plt.ylabel('真实标签')
            plt.title('混淆矩阵')
            plt.tight_layout()
            plt.savefig(cm_path)
            plt.close()
            
            # 绘制ROC曲线（多分类）
            roc_path = os.path.join(eval_dir, f"{model_name}_roc_curve.png")
            n_classes = len(self.ATTACK_TYPES)
            y_true_bin = label_binarize(y_true, classes=range(n_classes))
            
            plt.figure(figsize=(10, 8))
            # 计算每个类别的ROC曲线
            for i in range(n_classes):
                fpr, tpr, _ = roc_curve(y_true_bin[:, i], y_score[:, i])
                roc_auc = auc(fpr, tpr)
                plt.plot(fpr, tpr, lw=2, label=f'{self.ATTACK_TYPES[i]} (AUC = {roc_auc:.4f})')
            
            # 计算micro-average ROC曲线
            fpr_micro, tpr_micro, _ = roc_curve(y_true_bin.ravel(), y_score.ravel())
            roc_auc_micro = auc(fpr_micro, tpr_micro)
            plt.plot(fpr_micro, tpr_micro, color='deeppink', linestyle=':', lw=2,
                    label=f'Micro-average (AUC = {roc_auc_micro:.4f})')
            
            plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('假阳性率')
            plt.ylabel('真阳性率')
            plt.title('ROC曲线')
            plt.legend(loc="lower right", fontsize=8)
            plt.tight_layout()
            plt.savefig(roc_path)
            plt.close()
            
            # 绘制PR曲线（多分类）
            pr_path = os.path.join(eval_dir, f"{model_name}_pr_curve.png")
            plt.figure(figsize=(10, 8))
            
            for i in range(n_classes):
                prec, rec, _ = precision_recall_curve(y_true_bin[:, i], y_score[:, i])
                avg_prec = np.mean(prec)
                plt.plot(rec, prec, lw=2, label=f'{self.ATTACK_TYPES[i]} (AP = {avg_prec:.4f})')
            
            plt.xlabel('召回率')
            plt.ylabel('精确率')
            plt.title('精确率-召回率曲线')
            plt.legend(loc="lower left", fontsize=8)
            plt.tight_layout()
            plt.savefig(pr_path)
            plt.close()
            
            # 计算每个类别的精确率、召回率、F1分数
            from sklearn.metrics import classification_report
            report = classification_report(y_true, y_pred, 
                                         target_names=self.ATTACK_TYPES,
                                         output_dict=True, zero_division=0)
            
            return {
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "confusion_matrix": cm.tolist(),
                "confusion_matrix_image": f"/eval_results/{model_name}_confusion_matrix.png",
                "roc_curve_image": f"/eval_results/{model_name}_roc_curve.png",
                "pr_curve_image": f"/eval_results/{model_name}_pr_curve.png",
                "classification_report": report,
                "eval_dir": eval_dir
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"error": str(e)}
    
    def evaluate_binary_model(self, model_path: str, test_data_path: str) -> dict:
        """评估二分类模型"""
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            import seaborn as sns
            
            # 设置中文字体
            plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'Arial Unicode MS', 'DejaVu Sans']
            plt.rcParams['axes.unicode_minus'] = False
            
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
            from sklearn.metrics import roc_curve, auc, precision_recall_curve
            
            # 加载测试数据
            X_train, X_test, y_train, y_test, _ = load_cicids2017(test_data_path)
            
            # 转换为二分类标签
            y_test_binary = (y_test > 0).astype(int)
            
            # 加载模型
            input_dim = X_test.shape[1]
            if not self.load_model(model_path, "binary", input_dim=input_dim):
                return {"error": "二分类模型加载失败"}
            
            # 评估
            self._current_model.eval()
            y_true = []
            y_pred = []
            y_score = []  # 用于ROC曲线
            
            X_test_tensor = torch.FloatTensor(X_test).to(self._device)
            y_test_tensor = torch.LongTensor(y_test_binary)
            
            batch_size = 64
            with torch.no_grad():
                for i in range(0, len(X_test_tensor), batch_size):
                    batch = X_test_tensor[i:i+batch_size]
                    outputs = self._current_model(batch)
                    _, predicted = torch.max(outputs, 1)
                    # 获取异常类别的概率分数
                    scores = torch.softmax(outputs, dim=1)[:, 1].cpu().numpy()
                    y_pred.extend(predicted.cpu().numpy())
                    y_true.extend(y_test_tensor[i:i+batch_size].cpu().numpy())
                    y_score.extend(scores)
            
            y_true = np.array(y_true)
            y_pred = np.array(y_pred)
            y_score = np.array(y_score)
            
            # 计算指标
            accuracy = accuracy_score(y_true, y_pred)
            precision = precision_score(y_true, y_pred, average='weighted', zero_division=0)
            recall = recall_score(y_true, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)
            cm = confusion_matrix(y_true, y_pred)
            
            # 生成图表
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            eval_dir = os.path.join(base_dir, 'eval_results')
            os.makedirs(eval_dir, exist_ok=True)
            model_name = os.path.basename(model_path).replace('.pth', '')
            
            # 绘制混淆矩阵
            cm_path = os.path.join(eval_dir, f"{model_name}_confusion_matrix.png")
            plt.figure(figsize=(8, 6))
            binary_labels = ["正常(BENIGN)", "异常(Attack)"]
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False,
                       xticklabels=binary_labels, yticklabels=binary_labels)
            plt.xlabel('预测标签')
            plt.ylabel('真实标签')
            plt.title('二分类混淆矩阵')
            plt.tight_layout()
            plt.savefig(cm_path)
            plt.close()
            
            # 绘制ROC曲线
            roc_path = os.path.join(eval_dir, f"{model_name}_roc_curve.png")
            fpr, tpr, _ = roc_curve(y_true, y_score)
            roc_auc = auc(fpr, tpr)
            
            plt.figure(figsize=(8, 6))
            plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC曲线 (AUC = {roc_auc:.4f})')
            plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('假阳性率')
            plt.ylabel('真阳性率')
            plt.title('ROC曲线')
            plt.legend(loc="lower right")
            plt.tight_layout()
            plt.savefig(roc_path)
            plt.close()
            
            # 绘制PR曲线
            pr_path = os.path.join(eval_dir, f"{model_name}_pr_curve.png")
            prec, rec, _ = precision_recall_curve(y_true, y_score)
            avg_precision = np.mean(prec)
            
            plt.figure(figsize=(8, 6))
            plt.plot(rec, prec, color='blue', lw=2, label=f'精确率-召回率曲线 (AP = {avg_precision:.4f})')
            plt.xlabel('召回率')
            plt.ylabel('精确率')
            plt.title('精确率-召回率曲线')
            plt.legend(loc="lower left")
            plt.tight_layout()
            plt.savefig(pr_path)
            plt.close()
            
            # 计算分类报告
            from sklearn.metrics import classification_report
            report = classification_report(y_true, y_pred, 
                                         target_names=binary_labels,
                                         output_dict=True, zero_division=0)
            
            return {
                "success": True,
                "model_type": "binary",
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "confusion_matrix": cm.tolist(),
                "confusion_matrix_image": f"/eval_results/{model_name}_confusion_matrix.png",
                "roc_curve_image": f"/eval_results/{model_name}_roc_curve.png",
                "pr_curve_image": f"/eval_results/{model_name}_pr_curve.png",
                "classification_report": report,
                "eval_dir": eval_dir
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"error": str(e)}
    
    def evaluate_two_stage_model(self, binary_model_path: str, test_data_path: str, dataset_type: str) -> dict:
        """评估两阶段模型（分别评估二分类和六分类）"""
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            import seaborn as sns
            
            # 设置中文字体
            plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'Arial Unicode MS', 'DejaVu Sans']
            plt.rcParams['axes.unicode_minus'] = False
            
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
            from sklearn.metrics import roc_curve, auc, precision_recall_curve
            from sklearn.preprocessing import label_binarize
            
            # 加载测试数据
            X_train, X_test, y_train, y_test, _ = load_cicids2017(test_data_path)
            
            # 构建六分类模型路径
            attack_model_path = binary_model_path.replace('binary_', 'attack_')
            
            # 加载两阶段模型
            input_dim = X_test.shape[1]
            if not self.load_two_stage_model(binary_model_path, attack_model_path, scaler_path=None, input_dim=input_dim):
                return {"error": "两阶段模型加载失败"}
            
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            eval_dir = os.path.join(base_dir, 'eval_results')
            os.makedirs(eval_dir, exist_ok=True)
            model_name = os.path.basename(binary_model_path).replace('.pth', '')
            
            # ========== 评估二分类部分 ==========
            y_test_binary = (y_test > 0).astype(int)
            self._binary_model.eval()
            y_true_binary = []
            y_pred_binary = []
            y_score_binary = []  # 用于ROC曲线
            
            X_test_tensor = torch.FloatTensor(X_test).to(self._device)
            y_test_binary_tensor = torch.LongTensor(y_test_binary)
            
            batch_size = 64
            with torch.no_grad():
                for i in range(0, len(X_test_tensor), batch_size):
                    batch = X_test_tensor[i:i+batch_size]
                    outputs = self._binary_model(batch)
                    _, predicted = torch.max(outputs, 1)
                    # 获取异常类别的概率分数
                    scores = torch.softmax(outputs, dim=1)[:, 1].cpu().numpy()
                    y_pred_binary.extend(predicted.cpu().numpy())
                    y_true_binary.extend(y_test_binary_tensor[i:i+batch_size].cpu().numpy())
                    y_score_binary.extend(scores)
            
            y_true_binary = np.array(y_true_binary)
            y_pred_binary = np.array(y_pred_binary)
            y_score_binary = np.array(y_score_binary)
            
            binary_accuracy = accuracy_score(y_true_binary, y_pred_binary)
            binary_precision = precision_score(y_true_binary, y_pred_binary, average='weighted', zero_division=0)
            binary_recall = recall_score(y_true_binary, y_pred_binary, average='weighted', zero_division=0)
            binary_f1 = f1_score(y_true_binary, y_pred_binary, average='weighted', zero_division=0)
            cm_binary = confusion_matrix(y_true_binary, y_pred_binary)
            
            # 绘制二分类混淆矩阵
            cm_binary_path = os.path.join(eval_dir, f"{model_name}_binary_confusion_matrix.png")
            plt.figure(figsize=(8, 6))
            binary_labels = ["正常(BENIGN)", "异常(Attack)"]
            sns.heatmap(cm_binary, annot=True, fmt='d', cmap='Blues', cbar=False,
                       xticklabels=binary_labels, yticklabels=binary_labels)
            plt.xlabel('预测标签')
            plt.ylabel('真实标签')
            plt.title('二分类混淆矩阵（第一阶段）')
            plt.tight_layout()
            plt.savefig(cm_binary_path)
            plt.close()
            
            # 绘制二分类ROC曲线
            roc_binary_path = os.path.join(eval_dir, f"{model_name}_binary_roc_curve.png")
            fpr, tpr, _ = roc_curve(y_true_binary, y_score_binary)
            roc_auc = auc(fpr, tpr)
            
            plt.figure(figsize=(8, 6))
            plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC曲线 (AUC = {roc_auc:.4f})')
            plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('假阳性率')
            plt.ylabel('真阳性率')
            plt.title('二分类ROC曲线（第一阶段）')
            plt.legend(loc="lower right")
            plt.tight_layout()
            plt.savefig(roc_binary_path)
            plt.close()
            
            # 绘制二分类PR曲线
            pr_binary_path = os.path.join(eval_dir, f"{model_name}_binary_pr_curve.png")
            prec, rec, _ = precision_recall_curve(y_true_binary, y_score_binary)
            avg_precision = np.mean(prec)
            
            plt.figure(figsize=(8, 6))
            plt.plot(rec, prec, color='blue', lw=2, label=f'精确率-召回率曲线 (AP = {avg_precision:.4f})')
            plt.xlabel('召回率')
            plt.ylabel('精确率')
            plt.title('二分类精确率-召回率曲线（第一阶段）')
            plt.legend(loc="lower left")
            plt.tight_layout()
            plt.savefig(pr_binary_path)
            plt.close()
            
            from sklearn.metrics import classification_report
            binary_report = classification_report(y_true_binary, y_pred_binary, 
                                                 target_names=binary_labels,
                                                 output_dict=True, zero_division=0)
            
            binary_results = {
                "accuracy": binary_accuracy,
                "precision": binary_precision,
                "recall": binary_recall,
                "f1_score": binary_f1,
                "confusion_matrix": cm_binary.tolist(),
                "confusion_matrix_image": f"/eval_results/{model_name}_binary_confusion_matrix.png",
                "roc_curve_image": f"/eval_results/{model_name}_binary_roc_curve.png",
                "pr_curve_image": f"/eval_results/{model_name}_binary_pr_curve.png",
                "classification_report": binary_report
            }
            
            # ========== 评估六分类部分 ==========
            # 只使用异常流量进行六分类评估
            attack_mask = (y_test > 0)
            X_test_attack = X_test[attack_mask]
            y_test_attack = y_test[attack_mask] - 1  # 映射到0-5
            
            self._attack_model.eval()
            y_true_attack = []
            y_pred_attack = []
            y_score_attack = []  # 用于ROC曲线
            
            X_test_attack_tensor = torch.FloatTensor(X_test_attack).to(self._device)
            y_test_attack_tensor = torch.LongTensor(y_test_attack.values if hasattr(y_test_attack, 'values') else y_test_attack)
            
            with torch.no_grad():
                for i in range(0, len(X_test_attack_tensor), batch_size):
                    batch = X_test_attack_tensor[i:i+batch_size]
                    outputs = self._attack_model(batch)
                    _, predicted = torch.max(outputs, 1)
                    # 获取概率分数用于ROC曲线
                    scores = torch.softmax(outputs, dim=1).cpu().numpy()
                    y_pred_attack.extend(predicted.cpu().numpy())
                    y_true_attack.extend(y_test_attack_tensor[i:i+batch_size].cpu().numpy())
                    y_score_attack.extend(scores)
            
            y_true_attack = np.array(y_true_attack)
            y_pred_attack = np.array(y_pred_attack)
            y_score_attack = np.array(y_score_attack)
            
            attack_accuracy = accuracy_score(y_true_attack, y_pred_attack)
            attack_precision = precision_score(y_true_attack, y_pred_attack, average='weighted', zero_division=0)
            attack_recall = recall_score(y_true_attack, y_pred_attack, average='weighted', zero_division=0)
            attack_f1 = f1_score(y_true_attack, y_pred_attack, average='weighted', zero_division=0)
            cm_attack = confusion_matrix(y_true_attack, y_pred_attack)
            
            # 绘制六分类混淆矩阵
            cm_attack_path = os.path.join(eval_dir, f"{model_name}_attack_confusion_matrix.png")
            plt.figure(figsize=(10, 8))
            attack_labels = ["Bot", "BruteForce", "DoS", "Infiltration", "PortScan", "WebAttack"]
            sns.heatmap(cm_attack, annot=True, fmt='d', cmap='Blues', cbar=False,
                       xticklabels=attack_labels, yticklabels=attack_labels)
            plt.xlabel('预测标签')
            plt.ylabel('真实标签')
            plt.title('六分类混淆矩阵（第二阶段）')
            plt.tight_layout()
            plt.savefig(cm_attack_path)
            plt.close()
            
            # 绘制六分类ROC曲线
            roc_attack_path = os.path.join(eval_dir, f"{model_name}_attack_roc_curve.png")
            n_classes = len(attack_labels)
            y_true_attack_bin = label_binarize(y_true_attack, classes=range(n_classes))
            
            plt.figure(figsize=(10, 8))
            for i in range(n_classes):
                fpr, tpr, _ = roc_curve(y_true_attack_bin[:, i], y_score_attack[:, i])
                roc_auc = auc(fpr, tpr)
                plt.plot(fpr, tpr, lw=2, label=f'{attack_labels[i]} (AUC = {roc_auc:.4f})')
            
            # Micro-average ROC曲线
            fpr_micro, tpr_micro, _ = roc_curve(y_true_attack_bin.ravel(), y_score_attack.ravel())
            roc_auc_micro = auc(fpr_micro, tpr_micro)
            plt.plot(fpr_micro, tpr_micro, color='deeppink', linestyle=':', lw=2,
                    label=f'Micro-average (AUC = {roc_auc_micro:.4f})')
            
            plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('假阳性率')
            plt.ylabel('真阳性率')
            plt.title('六分类ROC曲线（第二阶段）')
            plt.legend(loc="lower right", fontsize=8)
            plt.tight_layout()
            plt.savefig(roc_attack_path)
            plt.close()
            
            # 绘制六分类PR曲线
            pr_attack_path = os.path.join(eval_dir, f"{model_name}_attack_pr_curve.png")
            plt.figure(figsize=(10, 8))
            
            for i in range(n_classes):
                prec, rec, _ = precision_recall_curve(y_true_attack_bin[:, i], y_score_attack[:, i])
                avg_prec = np.mean(prec)
                plt.plot(rec, prec, lw=2, label=f'{attack_labels[i]} (AP = {avg_prec:.4f})')
            
            plt.xlabel('召回率')
            plt.ylabel('精确率')
            plt.title('六分类精确率-召回率曲线（第二阶段）')
            plt.legend(loc="lower left", fontsize=8)
            plt.tight_layout()
            plt.savefig(pr_attack_path)
            plt.close()
            
            attack_report = classification_report(y_true_attack, y_pred_attack, 
                                                 target_names=attack_labels,
                                                 output_dict=True, zero_division=0)
            
            attack_results = {
                "accuracy": attack_accuracy,
                "precision": attack_precision,
                "recall": attack_recall,
                "f1_score": attack_f1,
                "confusion_matrix": cm_attack.tolist(),
                "confusion_matrix_image": f"/eval_results/{model_name}_attack_confusion_matrix.png",
                "roc_curve_image": f"/eval_results/{model_name}_attack_roc_curve.png",
                "pr_curve_image": f"/eval_results/{model_name}_attack_pr_curve.png",
                "classification_report": attack_report
            }
            
            return {
                "success": True,
                "model_type": "two_stage",
                "accuracy": attack_accuracy,  # 主准确率使用六分类
                "precision": attack_precision,
                "recall": attack_recall,
                "f1_score": attack_f1,
                "binary_results": binary_results,
                "attack_results": attack_results,
                "eval_dir": eval_dir
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"error": str(e)}
