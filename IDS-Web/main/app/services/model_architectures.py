import torch
import torch.nn as nn
import torch.nn.functional as F

class FocalLoss(nn.Module):
    """
    Focal Loss for handling class imbalance
    
    参考论文：Lin et al., "Focal Loss for Dense Object Detection", ICCV 2017
    
    参数:
        gamma: 焦点参数，默认为2
        weight: 类别权重，默认为None
    """
    def __init__(self, gamma=2, weight=None):
        super(FocalLoss, self).__init__()
        self.gamma = gamma
        self.weight = weight

    def forward(self, input, target):
        ce_loss = nn.CrossEntropyLoss(weight=self.weight)(input, target)
        pt = torch.exp(-ce_loss)
        loss = ((1 - pt) ** self.gamma * ce_loss).mean()
        return loss


class IDSConvNet(nn.Module):
    """
    一阶段CNN模型（七分类）：直接对七种流量类型进行分类
    
    参数:
        input_dim: 输入特征维度
        num_classes: 分类类别数，默认为7（七分类）
    """
    def __init__(self, input_dim, num_classes=7):
        super(IDSConvNet, self).__init__()
        
        # 第一个卷积块
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=64, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(64)
        self.pool1 = nn.MaxPool1d(kernel_size=2, stride=2)
        self.dropout1 = nn.Dropout(0.25)
        
        # 第二个卷积块
        self.conv2 = nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(128)
        self.pool2 = nn.MaxPool1d(kernel_size=2, stride=2)
        self.dropout2 = nn.Dropout(0.25)
        
        # 第三个卷积块
        self.conv3 = nn.Conv1d(in_channels=128, out_channels=256, kernel_size=3, padding=1)
        self.bn3 = nn.BatchNorm1d(256)
        self.pool3 = nn.MaxPool1d(kernel_size=2, stride=2)
        self.dropout3 = nn.Dropout(0.25)
        
        # 计算卷积层之后的特征维度
        self.feature_dim = (input_dim // 8) * 256
        
        # 全连接层
        self.fc1 = nn.Linear(self.feature_dim, 512)
        self.dropout4 = nn.Dropout(0.5)
        self.fc2 = nn.Linear(512, 128)
        self.fc3 = nn.Linear(128, num_classes)
        
    def forward(self, x):
        # 重塑输入以适应卷积操作
        x = x.unsqueeze(1)
        
        # 第一个卷积块
        x = self.conv1(x)
        x = self.bn1(x)
        x = F.relu(x)
        x = self.pool1(x)
        x = self.dropout1(x)
        
        # 第二个卷积块
        x = self.conv2(x)
        x = self.bn2(x)
        x = F.relu(x)
        x = self.pool2(x)
        x = self.dropout2(x)
        
        # 第三个卷积块
        x = self.conv3(x)
        x = self.bn3(x)
        x = F.relu(x)
        x = self.pool3(x)
        x = self.dropout3(x)
        
        # 展平
        x = x.view(x.size(0), -1)
        
        # 全连接层
        x = F.relu(self.fc1(x))
        x = self.dropout4(x)
        x = F.relu(self.fc2(x))
        x = self.fc3(x)
        
        return x


class IDSBinaryClassifier(nn.Module):
    """
    二分类模型：区分正常流量（BENIGN）和异常流量
    
    参数:
        input_dim: 输入特征维度
    """
    def __init__(self, input_dim):
        super(IDSBinaryClassifier, self).__init__()
        
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=64, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(64)
        self.pool1 = nn.MaxPool1d(kernel_size=2, stride=2)
        self.dropout1 = nn.Dropout(0.25)
        
        self.conv2 = nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(128)
        self.pool2 = nn.MaxPool1d(kernel_size=2, stride=2)
        self.dropout2 = nn.Dropout(0.25)
        
        self.conv3 = nn.Conv1d(in_channels=128, out_channels=256, kernel_size=3, padding=1)
        self.bn3 = nn.BatchNorm1d(256)
        self.pool3 = nn.MaxPool1d(kernel_size=2, stride=2)
        self.dropout3 = nn.Dropout(0.25)
        
        self.feature_dim = (input_dim // 8) * 256
        
        self.fc1 = nn.Linear(self.feature_dim, 512)
        self.dropout4 = nn.Dropout(0.5)
        self.fc2 = nn.Linear(512, 128)
        self.fc3 = nn.Linear(128, 2)
        
    def forward(self, x):
        x = x.unsqueeze(1)
        
        x = self.conv1(x)
        x = self.bn1(x)
        x = F.relu(x)
        x = self.pool1(x)
        x = self.dropout1(x)
        
        x = self.conv2(x)
        x = self.bn2(x)
        x = F.relu(x)
        x = self.pool2(x)
        x = self.dropout2(x)
        
        x = self.conv3(x)
        x = self.bn3(x)
        x = F.relu(x)
        x = self.pool3(x)
        x = self.dropout3(x)
        
        x = x.view(x.size(0), -1)
        
        x = self.fc1(x)
        x = F.relu(x)
        x = self.dropout4(x)
        x = self.fc2(x)
        x = F.relu(x)
        x = self.fc3(x)
        
        return x


class IDSAttackClassifier(nn.Module):
    """
    六分类模型：对异常流量进行分类（Bot, BruteForce, DoS, Infiltration, PortScan, WebAttack）
    
    参数:
        input_dim: 输入特征维度
    """
    def __init__(self, input_dim):
        super(IDSAttackClassifier, self).__init__()
        
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=64, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(64)
        self.pool1 = nn.MaxPool1d(kernel_size=2, stride=2)
        self.dropout1 = nn.Dropout(0.25)
        
        self.conv2 = nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(128)
        self.pool2 = nn.MaxPool1d(kernel_size=2, stride=2)
        self.dropout2 = nn.Dropout(0.25)
        
        self.conv3 = nn.Conv1d(in_channels=128, out_channels=256, kernel_size=3, padding=1)
        self.bn3 = nn.BatchNorm1d(256)
        self.pool3 = nn.MaxPool1d(kernel_size=2, stride=2)
        self.dropout3 = nn.Dropout(0.25)
        
        self.feature_dim = (input_dim // 8) * 256
        
        self.fc1 = nn.Linear(self.feature_dim, 512)
        self.dropout4 = nn.Dropout(0.5)
        self.fc2 = nn.Linear(512, 128)
        self.fc3 = nn.Linear(128, 6)
        
    def forward(self, x):
        x = x.unsqueeze(1)
        
        x = self.conv1(x)
        x = self.bn1(x)
        x = F.relu(x)
        x = self.pool1(x)
        x = self.dropout1(x)
        
        x = self.conv2(x)
        x = self.bn2(x)
        x = F.relu(x)
        x = self.pool2(x)
        x = self.dropout2(x)
        
        x = self.conv3(x)
        x = self.bn3(x)
        x = F.relu(x)
        x = self.pool3(x)
        x = self.dropout3(x)
        
        x = x.view(x.size(0), -1)
        
        x = self.fc1(x)
        x = F.relu(x)
        x = self.dropout4(x)
        x = self.fc2(x)
        x = F.relu(x)
        x = self.fc3(x)
        
        return x


class TwoStageIDS(nn.Module):
    """
    两阶段入侵检测模型：
    1. 第一阶段：二分类（正常vs异常）
    2. 第二阶段：六分类（对异常流量进行分类）
    
    参数:
        input_dim: 输入特征维度
    """
    def __init__(self, input_dim):
        super(TwoStageIDS, self).__init__()
        self.binary_classifier = IDSBinaryClassifier(input_dim)
        self.attack_classifier = IDSAttackClassifier(input_dim)
        
    def forward(self, x):
        binary_output = self.binary_classifier(x)
        return binary_output
    
    def predict(self, x, device='cuda'):
        """
        两阶段预测
        
        参数:
            x: 输入特征
            device: 设备
            
        返回:
            final_label: 最终标签（0=BENIGN, 1=Bot, 2=BruteForce, 3=DoS, 4=Infiltration, 5=PortScan, 6=WebAttack）
            binary_prob: 二分类概率
            attack_prob: 六分类概率（如果是异常流量）
        """
        self.eval()
        with torch.no_grad():
            x = x.to(device)
            
            binary_output = self.binary_classifier(x)
            binary_prob = F.softmax(binary_output, dim=1)
            binary_pred = binary_prob.argmax(dim=1)
            
            final_label = binary_pred.clone()
            attack_prob = None
            
            mask = (binary_pred == 1)
            if mask.any():
                attack_input = x[mask]
                attack_output = self.attack_classifier(attack_input)
                attack_prob_temp = F.softmax(attack_output, dim=1)
                attack_pred = attack_prob_temp.argmax(dim=1)
                
                final_label[mask] = attack_pred + 1
                attack_prob = torch.zeros(x.size(0), 6).to(device)
                attack_prob[mask] = attack_prob_temp
        
        return final_label, binary_prob, attack_prob
