import os
import numpy as np
import pandas as pd
import torch
import joblib
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler, LabelEncoder, OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from scipy import sparse
import warnings
warnings.filterwarnings("ignore")
from tqdm import tqdm

def load_cicids2017(data_path, test_size=0.2, random_state=42):
    meaningful_features = [
        'Flow Duration',
        'Total Fwd Packets',
        'Total Backward Packets',
        'Total Length of Fwd Packets',
        'Total Length of Bwd Packets',
        'Fwd Packet Length Max',
        'Fwd Packet Length Min',
        'Fwd Packet Length Mean',
        'Bwd Packet Length Max',
        'Bwd Packet Length Min',
        'Bwd Packet Length Mean',
        'Flow Bytes/s',
        'Flow Packets/s',
        'Fwd Header Length',
        'Bwd Header Length',
        'Fwd Packets/s',
        'Bwd Packets/s',
        'Min Packet Length',
        'Max Packet Length',
        'Packet Length Mean',
        'Packet Length Std',
        'Packet Length Variance',
        'Fwd IAT Mean',
        'Bwd IAT Mean',
        'Active Mean',
        'Idle Mean',
    ]
    
    all_files = []
    for file in os.listdir(data_path):
        if file.endswith('.csv'):
            file_path = os.path.join(data_path, file)
            df = pd.read_csv(file_path)
            all_files.append(df)
    
    df = pd.concat(all_files, axis=0, ignore_index=True)
    X = df[meaningful_features]
    # 多分类标签映射
    label_map = {
        'BENIGN': 0,
        'Bot': 1,
        'BruteForce': 2,
        'DoS': 3,
        'Infiltration': 4,
        'PortScan': 5,
        'WebAttack': 6
    }
    y = df['Label'].map(label_map).fillna(0).astype(int)
    
    # 处理无穷大和异常值
    # 1. 将无穷大替换为NaN
    X = X.replace([np.inf, -np.inf], np.nan)
    
    # 2. 使用中位数填充NaN值
    X = X.fillna(X.median())
    
    # 3. 处理异常值（使用IQR方法）
    for column in X.columns:
        Q1 = X[column].quantile(0.25)
        Q3 = X[column].quantile(0.75)
        IQR = Q3 - Q1
        lower_bound = Q1 - 1.5 * IQR
        upper_bound = Q3 + 1.5 * IQR
        
        # 将超出范围的值替换为边界值
        X[column] = X[column].clip(lower_bound, upper_bound)
    
    # 创建StandardScaler
    scaler = StandardScaler()
    
    # 拟合和转换数据
    X_processed = scaler.fit_transform(X)
    
    # 将处理后的数据分割为训练集和测试集
    X_train_processed, X_test_processed, y_train, y_test = train_test_split(
        X_processed, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    return X_train_processed, X_test_processed, y_train.values, y_test.values, scaler

def get_dataset_loader(dataset_name, data_path, batch_size=64, test_size=0.2, random_state=42, use_10_percent=True):
    if dataset_name.lower() == 'cicids2017':
        X_train, X_test, y_train, y_test, _ = load_cicids2017(data_path, test_size, random_state)
    elif dataset_name.lower() == 'custom':
        X_train, X_test, y_train, y_test, _ = load_cicids2017(data_path, test_size, random_state)
    else:
        raise ValueError(f"不支持的数据集: {dataset_name}")
    
    if sparse.issparse(X_train):
        X_train = X_train.toarray()
    if sparse.issparse(X_test):
        X_test = X_test.toarray()
    
    # 转换为PyTorch张量
    X_train_tensor = torch.FloatTensor(X_train)
    X_test_tensor = torch.FloatTensor(X_test)
    y_train_tensor = torch.LongTensor(y_train)
    y_test_tensor = torch.LongTensor(y_test)
    
    train_dataset = TensorDataset(X_train_tensor, y_train_tensor)
    test_dataset = TensorDataset(X_test_tensor, y_test_tensor)
    
    # 创建数据加载器
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
    
    feature_dim = X_train.shape[1]

    return train_loader, test_loader, feature_dim

def get_two_stage_dataset_loaders(dataset_name, data_path, batch_size=64, test_size=0.2, random_state=42):
    """
    获取两阶段分类的数据加载器
    
    参数:
        dataset_name: 数据集名称
        data_path: 数据集路径
        batch_size: 批次大小
        test_size: 测试集比例
        random_state: 随机种子
        
    返回:
        binary_train_loader: 二分类训练数据加载器
        binary_test_loader: 二分类测试数据加载器
        attack_train_loader: 六分类训练数据加载器
        attack_test_loader: 六分类测试数据加载器
        feature_dim: 特征维度
        scaler: 标准化器
    """
    if dataset_name.lower() == 'cicids2017':
        X_train, X_test, y_train, y_test, scaler = load_cicids2017(data_path, test_size, random_state)
    elif dataset_name.lower() == 'custom':
        X_train, X_test, y_train, y_test, scaler = load_cicids2017(data_path, test_size, random_state)
    else:
        raise ValueError(f"不支持的数据集: {dataset_name}")
    
    if sparse.issparse(X_train):
        X_train = X_train.toarray()
    if sparse.issparse(X_test):
        X_test = X_test.toarray()
    
    feature_dim = X_train.shape[1]
    
    # 二分类标签：0=BENIGN, 1=异常
    y_train_binary = (y_train > 0).astype(int)
    y_test_binary = (y_test > 0).astype(int)
    
    # 六分类标签：只包含异常流量，映射为0-5
    # 原始标签：1=Bot, 2=BruteForce, 3=DoS, 4=Infiltration, 5=PortScan, 6=WebAttack
    # 新标签：0=Bot, 1=BruteForce, 2=DoS, 3=Infiltration, 4=PortScan, 5=WebAttack
    
    # 获取异常流量的索引
    train_attack_mask = (y_train > 0)
    test_attack_mask = (y_test > 0)
    
    # 提取异常流量数据
    X_train_attack = X_train[train_attack_mask]
    y_train_attack = y_train[train_attack_mask] - 1  # 从1-6映射到0-5
    
    X_test_attack = X_test[test_attack_mask]
    y_test_attack = y_test[test_attack_mask] - 1  # 从1-6映射到0-5
    
    # 转换为PyTorch张量
    # 二分类
    X_train_tensor = torch.FloatTensor(X_train)
    X_test_tensor = torch.FloatTensor(X_test)
    y_train_binary_tensor = torch.LongTensor(y_train_binary)
    y_test_binary_tensor = torch.LongTensor(y_test_binary)
    
    # 六分类
    X_train_attack_tensor = torch.FloatTensor(X_train_attack)
    X_test_attack_tensor = torch.FloatTensor(X_test_attack)
    y_train_attack_tensor = torch.LongTensor(y_train_attack)
    y_test_attack_tensor = torch.LongTensor(y_test_attack)
    
    # 创建数据集
    binary_train_dataset = TensorDataset(X_train_tensor, y_train_binary_tensor)
    binary_test_dataset = TensorDataset(X_test_tensor, y_test_binary_tensor)
    
    attack_train_dataset = TensorDataset(X_train_attack_tensor, y_train_attack_tensor)
    attack_test_dataset = TensorDataset(X_test_attack_tensor, y_test_attack_tensor)
    
    # 创建数据加载器
    binary_train_loader = DataLoader(binary_train_dataset, batch_size=batch_size, shuffle=True)
    binary_test_loader = DataLoader(binary_test_dataset, batch_size=batch_size, shuffle=False)
    
    attack_train_loader = DataLoader(attack_train_dataset, batch_size=batch_size, shuffle=True)
    attack_test_loader = DataLoader(attack_test_dataset, batch_size=batch_size, shuffle=False)
    
    return binary_train_loader, binary_test_loader, attack_train_loader, attack_test_loader, feature_dim, scaler


def train_model(model, train_loader, val_loader, n_epochs=30, learning_rate=0.001, 
               device='cuda', patience=5, model_save_path=None, progress_callback=None, 
               use_focal_loss=True, class_weights=None, use_data_augmentation=True):
    """
    训练模型
    
    参数:
        model: 模型实例
        train_loader: 训练数据加载器
        val_loader: 验证数据加载器
        n_epochs: 训练轮数
        learning_rate: 学习率
        device: 训练设备
        patience: 早停耐心值
        model_save_path: 模型保存路径
        progress_callback: 进度回调函数，接收(current_epoch, total_epochs, progress_percent, loss, accuracy)
        use_focal_loss: 是否使用Focal Loss
        class_weights: 类别权重
        use_data_augmentation: 是否使用数据增强
    """
    model = model.to(device)
    
    # 导入Focal Loss
    from app.services.model_architectures import FocalLoss
    
    # 准备类别权重
    if class_weights is not None:
        class_weights = torch.tensor(class_weights).to(device)
    
    # 选择损失函数
    if use_focal_loss:
        criterion = FocalLoss(gamma=2, weight=class_weights)
    else:
        criterion = torch.nn.CrossEntropyLoss(weight=class_weights)
    
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    

    history = {
        'train_loss': [],
        'val_loss': [],
        'train_acc': [],
        'val_acc': [],
    }
    

    best_val_loss = float('inf')
    counter = 0
    

    # 训练循环
    for epoch in range(n_epochs):

        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0
        
        train_loop = tqdm(train_loader, desc=f'Epoch {epoch+1}/{n_epochs} [Train]')
        for inputs, targets in train_loop:

            inputs, targets = inputs.to(device), targets.to(device)
            
            # 数据增强
            if use_data_augmentation:
                # 添加少量高斯噪声
                noise = 0.01 * torch.randn_like(inputs)
                inputs = inputs + noise
            
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()
            
            # 统计
            train_loss += loss.item() * inputs.size(0)
            _, predicted = torch.max(outputs, 1)
            train_total += targets.size(0)
            train_correct += (predicted == targets).sum().item()
            
            # 更新
            train_loop.set_postfix({'loss': loss.item(), 'acc': train_correct / train_total})
            
        # 计算训练损失和准确率
        train_loss = train_loss / len(train_loader.dataset)
        train_acc = train_correct / train_total
        history['train_loss'].append(train_loss)
        history['train_acc'].append(train_acc)
        
        # 验证阶段
        model.eval()
        val_loss = 0.0
        val_correct = 0
        val_total = 0
        
        with torch.no_grad():
            val_loop = tqdm(val_loader, desc=f'Epoch {epoch+1}/{n_epochs} [Val]')
            for inputs, targets in val_loop:
                inputs, targets = inputs.to(device), targets.to(device)

                outputs = model(inputs)
                loss = criterion(outputs, targets)
                
                # 统计
                val_loss += loss.item() * inputs.size(0)
                _, predicted = torch.max(outputs, 1)
                val_total += targets.size(0)
                val_correct += (predicted == targets).sum().item()
                
                # 更新进度条
                val_loop.set_postfix({'loss': loss.item(), 'acc': val_correct / val_total})
                
        # 计算验证损失和准确率
        val_loss = val_loss / len(val_loader.dataset)
        val_acc = val_correct / val_total
        history['val_loss'].append(val_loss)
        history['val_acc'].append(val_acc)
        
        # 打印本轮训练结果
        print(f'Epoch {epoch+1}/{n_epochs} - '
              f'Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f} - '
              f'Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}')
        
        # 计算进度百分比
        progress_percent = int(((epoch + 1) / n_epochs) * 100)
        
        # 调用进度回调函数
        if progress_callback:
            progress_callback(epoch + 1, n_epochs, progress_percent, val_loss, val_acc)
        
        # 检查是否需要早停
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            counter = 0
            # 保存最佳模型
            if model_save_path:
                torch.save(model.state_dict(), model_save_path)
        else:
            counter += 1
            if counter >= patience:
                print(f'Early stopping at epoch {epoch+1}')
                break
    
    # 加载最佳模型（如果有）
    if model_save_path:
        model.load_state_dict(torch.load(model_save_path))
    
    return model, history

def train_two_stage_model(binary_model, attack_model, binary_train_loader, binary_test_loader, 
                         attack_train_loader, attack_test_loader, n_epochs=30, learning_rate=0.001, 
                         device='cuda', patience=5, binary_model_save_path=None, attack_model_save_path=None, 
                         progress_callback=None):
    """
    训练两阶段模型
    
    参数:
        binary_model: 二分类模型实例
        attack_model: 六分类模型实例
        binary_train_loader: 二分类训练数据加载器
        binary_test_loader: 二分类测试数据加载器
        attack_train_loader: 六分类训练数据加载器
        attack_test_loader: 六分类测试数据加载器
        n_epochs: 训练轮数
        learning_rate: 学习率
        device: 训练设备
        patience: 早停耐心值
        binary_model_save_path: 二分类模型保存路径
        attack_model_save_path: 六分类模型保存路径
        progress_callback: 进度回调函数，接收(stage, current_epoch, total_epochs, progress_percent, loss, accuracy)
    """
    from app.services.model_architectures import FocalLoss
    
    # 二分类不考虑样本不平衡，使用标准交叉熵损失
    binary_criterion = torch.nn.CrossEntropyLoss()
    
    # 六分类考虑样本不平衡（处理样本不平衡）
    # 训练集分布：Bot (1966), BruteForce (2767), DoS (19035), Infiltration (36), PortScan (7946), WebAttack (2180)
    # 降低Infiltration权重以避免过度分类
    attack_class_counts = [1966, 2767, 19035, 36, 7946, 2180]
    total_attack_samples = sum(attack_class_counts)
    # 计算基础权重，但限制Infiltration的最大权重
    attack_class_weights = []
    for count in attack_class_counts:
        weight = total_attack_samples / count
        # 限制Infiltration的权重不超过100
        if count == 36:  # Infiltration
            weight = min(weight, 100.0)
        attack_class_weights.append(weight)
    attack_class_weights = torch.tensor(attack_class_weights).to(device)
    
    # 六分类使用Focal Loss处理样本不平衡
    attack_criterion = FocalLoss(gamma=2.5, weight=attack_class_weights)
    
    # 第一阶段：训练二分类模型
    print("=" * 50)
    print("第一阶段：训练二分类模型（正常 vs 异常）")
    print("=" * 50)
    
    binary_model = binary_model.to(device)
    binary_optimizer = torch.optim.Adam(binary_model.parameters(), lr=learning_rate)
    
    binary_history = {
        'train_loss': [],
        'val_loss': [],
        'train_acc': [],
        'val_acc': [],
    }
    
    best_binary_val_loss = float('inf')
    binary_counter = 0
    
    for epoch in range(n_epochs):
        binary_model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0
        
        train_loop = tqdm(binary_train_loader, desc=f'Binary Epoch {epoch+1}/{n_epochs} [Train]')
        for inputs, targets in train_loop:
            inputs, targets = inputs.to(device), targets.to(device)
            
            # 二分类不使用数据增强
            
            binary_optimizer.zero_grad()
            outputs = binary_model(inputs)
            loss = binary_criterion(outputs, targets)
            loss.backward()
            binary_optimizer.step()
            
            train_loss += loss.item() * inputs.size(0)
            _, predicted = torch.max(outputs, 1)
            train_total += targets.size(0)
            train_correct += (predicted == targets).sum().item()
            
            train_loop.set_postfix({'loss': loss.item(), 'acc': train_correct / train_total})
        
        train_loss = train_loss / len(binary_train_loader.dataset)
        train_acc = train_correct / train_total
        binary_history['train_loss'].append(train_loss)
        binary_history['train_acc'].append(train_acc)
        
        # 验证阶段
        binary_model.eval()
        val_loss = 0.0
        val_correct = 0
        val_total = 0
        
        with torch.no_grad():
            val_loop = tqdm(binary_test_loader, desc=f'Binary Epoch {epoch+1}/{n_epochs} [Val]')
            for inputs, targets in val_loop:
                inputs, targets = inputs.to(device), targets.to(device)
                
                outputs = binary_model(inputs)
                loss = binary_criterion(outputs, targets)
                
                val_loss += loss.item() * inputs.size(0)
                _, predicted = torch.max(outputs, 1)
                val_total += targets.size(0)
                val_correct += (predicted == targets).sum().item()
                
                val_loop.set_postfix({'loss': loss.item(), 'acc': val_correct / val_total})
        
        val_loss = val_loss / len(binary_test_loader.dataset)
        val_acc = val_correct / val_total
        binary_history['val_loss'].append(val_loss)
        binary_history['val_acc'].append(val_acc)
        
        print(f'Binary Epoch {epoch+1}/{n_epochs} - '
              f'Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f} - '
              f'Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}')
        
        # 调用进度回调函数
        progress_percent = int(((epoch + 1) / (n_epochs * 2)) * 100)
        if progress_callback:
            progress_callback('binary', epoch + 1, n_epochs, progress_percent, val_loss, val_acc)
        
        # 检查是否需要早停
        if val_loss < best_binary_val_loss:
            best_binary_val_loss = val_loss
            binary_counter = 0
            if binary_model_save_path:
                torch.save(binary_model.state_dict(), binary_model_save_path)
        else:
            binary_counter += 1
            if binary_counter >= patience:
                print(f'Binary model early stopping at epoch {epoch+1}')
                break
    
    if binary_model_save_path:
        binary_model.load_state_dict(torch.load(binary_model_save_path))
    
    # 第二阶段：训练六分类模型
    print("=" * 50)
    print("第二阶段：训练六分类模型（异常流量分类）")
    print("=" * 50)
    
    attack_model = attack_model.to(device)
    attack_optimizer = torch.optim.Adam(attack_model.parameters(), lr=learning_rate)
    
    attack_history = {
        'train_loss': [],
        'val_loss': [],
        'train_acc': [],
        'val_acc': [],
    }
    
    best_attack_val_loss = float('inf')
    attack_counter = 0
    
    for epoch in range(n_epochs):
        attack_model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0
        
        train_loop = tqdm(attack_train_loader, desc=f'Attack Epoch {epoch+1}/{n_epochs} [Train]')
        for inputs, targets in train_loop:
            inputs, targets = inputs.to(device), targets.to(device)
            
            # 数据增强
            noise = 0.01 * torch.randn_like(inputs)
            inputs = inputs + noise
            
            attack_optimizer.zero_grad()
            outputs = attack_model(inputs)
            loss = attack_criterion(outputs, targets)
            loss.backward()
            attack_optimizer.step()
            
            train_loss += loss.item() * inputs.size(0)
            _, predicted = torch.max(outputs, 1)
            train_total += targets.size(0)
            train_correct += (predicted == targets).sum().item()
            
            train_loop.set_postfix({'loss': loss.item(), 'acc': train_correct / train_total})
        
        train_loss = train_loss / len(attack_train_loader.dataset)
        train_acc = train_correct / train_total
        attack_history['train_loss'].append(train_loss)
        attack_history['train_acc'].append(train_acc)
        
        # 验证阶段
        attack_model.eval()
        val_loss = 0.0
        val_correct = 0
        val_total = 0
        
        with torch.no_grad():
            val_loop = tqdm(attack_test_loader, desc=f'Attack Epoch {epoch+1}/{n_epochs} [Val]')
            for inputs, targets in val_loop:
                inputs, targets = inputs.to(device), targets.to(device)
                
                outputs = attack_model(inputs)
                loss = attack_criterion(outputs, targets)
                
                val_loss += loss.item() * inputs.size(0)
                _, predicted = torch.max(outputs, 1)
                val_total += targets.size(0)
                val_correct += (predicted == targets).sum().item()
                
                val_loop.set_postfix({'loss': loss.item(), 'acc': val_correct / val_total})
        
        val_loss = val_loss / len(attack_test_loader.dataset)
        val_acc = val_correct / val_total
        attack_history['val_loss'].append(val_loss)
        attack_history['val_acc'].append(val_acc)
        
        print(f'Attack Epoch {epoch+1}/{n_epochs} - '
              f'Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f} - '
              f'Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}')
        
        # 调用进度回调函数
        progress_percent = int(((n_epochs + epoch + 1) / (n_epochs * 2)) * 100)
        if progress_callback:
            progress_callback('attack', epoch + 1, n_epochs, progress_percent, val_loss, val_acc)
        
        # 检查是否需要早停
        if val_loss < best_attack_val_loss:
            best_attack_val_loss = val_loss
            attack_counter = 0
            if attack_model_save_path:
                torch.save(attack_model.state_dict(), attack_model_save_path)
        else:
            attack_counter += 1
            if attack_counter >= patience:
                print(f'Attack model early stopping at epoch {epoch+1}')
                break
    
    if attack_model_save_path:
        attack_model.load_state_dict(torch.load(attack_model_save_path))
    
    return binary_model, attack_model, binary_history, attack_history
