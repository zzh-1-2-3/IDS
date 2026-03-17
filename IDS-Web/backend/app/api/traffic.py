from fastapi import APIRouter, Depends, UploadFile, File, Form, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
import os
import shutil
import pandas as pd
import numpy as np
import time

from app.core.database import get_db
from app.core.config import settings
from app.core.logger import log_detection
from app.api.auth import get_current_user
from app.services.traffic_service import TrafficService
from app.services.model_service import ModelService
from app.services.capture_service import capture_service
from app.services.strategy_service import StrategyService
from app.schemas.traffic import TrafficResponse, TrafficFilter, RealtimeTraffic

router = APIRouter()
model_service = ModelService()

@router.get("/list")
def get_traffic_list(
    skip: int = 0,
    limit: int = 100,
    src_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    attack_type: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """获取流量列表"""
    filters = TrafficFilter(
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        attack_type=attack_type,
        status=status
    )
    
    traffic_list = TrafficService.get_traffic_list(db, skip, limit, filters)
    total = TrafficService.get_traffic_count(db, filters)
    
    return {
        "items": traffic_list,
        "total": total
    }

@router.post("/clear")
def clear_all_traffic(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """清空所有流量数据"""
    try:
        result = TrafficService.clear_all_traffic(db)
        return {"success": True, "message": f"已清空 {result} 条流量记录"}
    except Exception as e:
        return {"success": False, "message": str(e)}

@router.post("/upload-pcap")
async def upload_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """上传并处理流量文件"""
    if not (file.filename.endswith('.pcap') or file.filename.endswith('.csv')):
        return {"success": False, "message": "请上传PCAP或CSV文件"}
    
    # 保存上传的文件
    upload_dir = settings.UPLOAD_DIR
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, file.filename)
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    # 根据文件类型选择处理方法
    if file.filename.endswith('.pcap'):
        # 后台处理PCAP文件
        background_tasks.add_task(process_pcap_file, file_path, db)
    else:
        # 后台处理CSV文件
        background_tasks.add_task(process_csv_file, file_path, db)
    
    return {"success": True, "message": "文件上传成功，正在处理中..."}

@router.post("/process-pcap")
def process_pcap(
    file_path: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """处理PCAP文件并检测"""
    result = process_pcap_file(file_path, db)
    return result

def process_csv_file(file_path: str, db: Session):
    """处理CSV文件的内部函数"""
    from app.services.detection_service import DetectionService
    import pandas as pd
    
    try:
        # 读取CSV文件
        df = pd.read_csv(file_path)
        
        # 处理每条流量记录
        for _, row in df.iterrows():
            # 提取特征
            features = {
                'Flow Duration': row.get('Flow Duration', 0),
                'Total Fwd Packets': row.get('Total Fwd Packets', 0),
                'Total Backward Packets': row.get('Total Backward Packets', 0),
                'Total Length of Fwd Packets': row.get('Total Length of Fwd Packets', 0),
                'Total Length of Bwd Packets': row.get('Total Length of Bwd Packets', 0),
                'Fwd Packet Length Max': row.get('Fwd Packet Length Max', 0),
                'Fwd Packet Length Min': row.get('Fwd Packet Length Min', 0),
                'Fwd Packet Length Mean': row.get('Fwd Packet Length Mean', 0),
                'Bwd Packet Length Max': row.get('Bwd Packet Length Max', 0),
                'Bwd Packet Length Min': row.get('Bwd Packet Length Min', 0),
                'Bwd Packet Length Mean': row.get('Bwd Packet Length Mean', 0),
                'Flow Bytes/s': row.get('Flow Bytes/s', 0),
                'Flow Packets/s': row.get('Flow Packets/s', 0),
                'Fwd Header Length': row.get('Fwd Header Length', 0),
                'Bwd Header Length': row.get('Bwd Header Length', 0),
                'Fwd Packets/s': row.get('Fwd Packets/s', 0),
                'Bwd Packets/s': row.get('Bwd Packets/s', 0),
                'Min Packet Length': row.get('Min Packet Length', 0),
                'Max Packet Length': row.get('Max Packet Length', 0),
                'Packet Length Mean': row.get('Packet Length Mean', 0),
                'Packet Length Std': row.get('Packet Length Std', 0),
                'Packet Length Variance': row.get('Packet Length Variance', 0),
                'Fwd IAT Mean': row.get('Fwd IAT Mean', 0),
                'Bwd IAT Mean': row.get('Bwd IAT Mean', 0),
                'Active Mean': row.get('Active Mean', 0),
                'Idle Mean': row.get('Idle Mean', 0)
            }
            
            # 提取流量信息
            src_ip = row.get('src_ip', '0.0.0.0')
            dst_ip = row.get('dst_ip', '0.0.0.0')
            src_port = int(row.get('src_port', 0))
            dst_port = int(row.get('dst_port', 0))
            protocol = row.get('protocol', 'TCP')
            packet_size = int(row.get('packet_size', 0))
            timestamp = row.get('timestamp', pd.Timestamp.now())
            
            # 检测流量
            detection_result = DetectionService.detect_traffic(
                features=features,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=packet_size,
                timestamp=timestamp
            )
            
            # 保存检测结果
            if detection_result:
                from app.models.traffic import Traffic
                from sqlalchemy import and_
                
                # 检查是否已存在相同的流量记录
                existing = db.query(Traffic).filter(
                    and_(
                        Traffic.src_ip == src_ip,
                        Traffic.dst_ip == dst_ip,
                        Traffic.src_port == src_port,
                        Traffic.dst_port == dst_port,
                        Traffic.protocol == protocol
                    )
                ).first()
                
                if not existing:
                    traffic = Traffic(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        packet_size=packet_size,
                        timestamp=timestamp,
                        status=detection_result['status'],
                        attack_type=detection_result['attack_type'],
                        confidence=detection_result['confidence']
                    )
                    db.add(traffic)
        
        db.commit()
        return {"success": True, "message": f"CSV文件处理完成，共处理 {len(df)} 条流量记录"}
    except Exception as e:
        print(f"处理CSV文件失败: {e}")
        import traceback
        traceback.print_exc()
        return {"success": False, "message": f"处理失败: {str(e)}"}

def process_pcap_file(file_path: str, db: Session):
    """处理PCAP文件的内部函数"""
    from app.services.detection_service import DetectionService
    
    try:
        from scapy.all import rdpcap
        
        packets = rdpcap(file_path)
        
        # 处理数据包并提取特征
        from app.services.capture_service import FlowManager, Flow
        
        flow_manager = FlowManager()
        
        for packet in packets:
            flow_manager.process_packet(packet)
        
        flows = flow_manager.get_all_flows()
        
        # 保存流量数据并进行检测
        for flow in flows:
            flow_info = flow.get_flow_info()
            features = flow.extract_features()
            
            if features:
                # 保存到数据库
                traffic_data = {
                    "src_ip": flow_info['src_ip'],
                    "src_port": flow_info['src_port'],
                    "dst_ip": flow_info['dst_ip'],
                    "dst_port": flow_info['dst_port'],
                    "protocol": flow_info['protocol'],
                    "packet_size": flow_info['packet_size'],
                    "flow_duration": features['Flow Duration'],
                    "fwd_packets": features['Total Fwd Packets'],
                    "bwd_packets": features['Total Backward Packets'],
                    "fwd_bytes": features['Total Length of Fwd Packets'],
                    "bwd_bytes": features['Total Length of Bwd Packets'],
                }
                
                # 使用模型检测
                feature_array = np.array(list(features.values()))
                attack_type, confidence, threat_level = model_service.predict(feature_array)
                
                traffic_data["status"] = "abnormal" if attack_type != "BENIGN" else "normal"
                traffic_data["attack_type"] = attack_type
                traffic_data["confidence"] = confidence
                
                TrafficService.create_traffic(db, traffic_data)
                
                # 自动执行策略
                strategy_result = StrategyService.auto_execute_strategy(
                    db, attack_type, threat_level, flow_info['src_ip']
                )
                response_strategy = strategy_result['strategy_name'] if strategy_result else None
                
                # 存入检测结果表
                detection_data = {
                    "src_ip": flow_info['src_ip'],
                    "src_port": flow_info['src_port'],
                    "dst_ip": flow_info['dst_ip'],
                    "dst_port": flow_info['dst_port'],
                    "protocol": flow_info['protocol'],
                    "packet_size": flow_info['packet_size'],
                    "attack_type": attack_type,
                    "confidence": confidence,
                    "threat_level": threat_level,
                    "response_strategy": response_strategy
                }
                DetectionService.create_detection(db, detection_data)
        
        return {"success": True, "message": f"处理完成，共处理{len(flows)}个流量流"}
    
    except Exception as e:
        return {"success": False, "message": f"处理失败: {str(e)}"}

@router.get("/interfaces")
def get_interfaces(current_user = Depends(get_current_user)):
    """获取可用网卡列表"""
    interfaces = capture_service.get_network_interfaces()
    return {"interfaces": interfaces}

@router.post("/start-realtime")
def start_realtime_capture(
    request: dict,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """开始实时捕获"""
    from app.services.detection_service import DetectionService
    
    interfaces = request.get("interfaces", [])
    update_interval = request.get("update_interval", 10)
    
    # 批量处理流量的函数
    def process_batch_flows(flows):
        """批量处理流量并进行检测"""
        from app.services.strategy_service import StrategyService
        
        for flow in flows:
            try:
                features = flow.extract_features()
                if features:
                    feature_array = np.array(list(features.values()))
                    attack_type, confidence, threat_level = model_service.predict(feature_array)
                    
                    flow_info = flow.get_flow_info()
                    traffic_data = {
                        "src_ip": flow_info['src_ip'],
                        "src_port": flow_info['src_port'],
                        "dst_ip": flow_info['dst_ip'],
                        "dst_port": flow_info['dst_port'],
                        "protocol": flow_info['protocol'],
                        "packet_size": flow_info['packet_size'],
                        "status": "abnormal" if attack_type != "BENIGN" else "normal",
                        "attack_type": attack_type,
                        "confidence": confidence
                    }
                    TrafficService.create_traffic(db, traffic_data)
                    
                    # 自动执行策略
                    strategy_result = StrategyService.auto_execute_strategy(
                        db, attack_type, threat_level, flow_info['src_ip']
                    )
                    response_strategy = strategy_result['strategy_name'] if strategy_result else None
                    
                    # 同时创建检测结果记录
                    detection_data = {
                        "src_ip": flow_info['src_ip'],
                        "src_port": flow_info['src_port'],
                        "dst_ip": flow_info['dst_ip'],
                        "dst_port": flow_info['dst_port'],
                        "protocol": flow_info['protocol'],
                        "packet_size": flow_info['packet_size'],
                        "attack_type": attack_type,
                        "confidence": confidence,
                        "threat_level": threat_level,
                        "response_strategy": response_strategy
                    }
                    DetectionService.create_detection(db, detection_data)
                    
                    log_detection(f"处理流量: {flow_info['src_ip']}:{flow_info['src_port']} -> {flow_info['dst_ip']}:{flow_info['dst_port']} {flow_info['protocol']}")
                    log_detection(f"检测结果: {attack_type} (置信度: {confidence:.2f}, 威胁等级: {threat_level})")
            except Exception as e:
                log_detection(f"处理流量数据失败: {e}")
    
    # 定期处理流量的回调
    def on_update(flows):
        """定期处理流量的回调"""
        if flows:
            log_detection(f"收到 {len(flows)} 个流量进行处理")
            process_batch_flows(flows)
    
    # 数据包处理回调 - 只处理实时信息，不存储
    def on_packet(flow_info):
        """数据包处理回调"""
        # 这里可以添加实时流量信息的处理，比如打印日志
        # 实际的存储和检测在定期处理中进行
        try:
            log_detection(f"实时捕获: {flow_info['src_ip']}:{flow_info['src_port']} -> {flow_info['dst_ip']}:{flow_info['dst_port']} {flow_info['protocol']}")
        except Exception as e:
            log_detection(f"实时处理流量数据失败: {e}")
    
    # 启动捕获
    success = capture_service.start_capture(
        interfaces=interfaces,
        duration=3600,  # 最多捕获1小时
        update_interval=update_interval,
        callback=on_packet
    )
    
    if success:
        # 用于跟踪已处理的流量
        processed_flows = set()
        
        # 批量处理流量的函数（带数据库会话管理）
        def process_batch_flows_with_db(flows):
            """批量处理流量并进行检测，使用独立的数据库会话"""
            from app.core.database import SessionLocal
            from app.services.strategy_service import StrategyService
            
            # 创建独立的数据库会话
            db_thread = SessionLocal()
            try:
                log_detection(f"开始处理 {len(flows)} 个流量")
                for idx, flow in enumerate(flows):
                    try:
                        log_detection(f"处理第 {idx+1}/{len(flows)} 个流量...")
                        features = flow.extract_features()
                        if features:
                            feature_array = np.array(list(features.values()))
                            
                            attack_type, confidence, threat_level = model_service.predict(feature_array)
                            log_detection(f"预测结果: {attack_type}, 置信度: {confidence:.4f}, 威胁等级: {threat_level}")
                            
                            flow_info = flow.get_flow_info()
                            traffic_data = {
                                "src_ip": flow_info['src_ip'],
                                "src_port": flow_info['src_port'],
                                "dst_ip": flow_info['dst_ip'],
                                "dst_port": flow_info['dst_port'],
                                "protocol": flow_info['protocol'],
                                "packet_size": flow_info['packet_size'],
                                "status": "abnormal" if attack_type != "BENIGN" else "normal",
                                "attack_type": attack_type,
                                "confidence": confidence
                            }
                            TrafficService.create_traffic(db_thread, traffic_data)
                            log_detection(f"流量数据已保存到数据库: {flow_info['src_ip']}:{flow_info['src_port']} -> {flow_info['dst_ip']}:{flow_info['dst_port']}")
                            
                            # 自动执行策略
                            strategy_result = StrategyService.auto_execute_strategy(
                                db_thread, attack_type, threat_level, flow_info['src_ip']
                            )
                            response_strategy = strategy_result['strategy_name'] if strategy_result else None
                            
                            # 同时创建检测结果记录
                            detection_data = {
                                "src_ip": flow_info['src_ip'],
                                "src_port": flow_info['src_port'],
                                "dst_ip": flow_info['dst_ip'],
                                "dst_port": flow_info['dst_port'],
                                "protocol": flow_info['protocol'],
                                "packet_size": flow_info['packet_size'],
                                "attack_type": attack_type,
                                "confidence": confidence,
                                "threat_level": threat_level,
                                "response_strategy": response_strategy
                            }
                            DetectionService.create_detection(db_thread, detection_data)
                            log_detection(f"检测结果数据已保存到数据库: {attack_type} (置信度: {confidence:.2f})")
                            
                            log_detection(f"成功处理流量: {flow_info['src_ip']}:{flow_info['src_port']} -> {flow_info['dst_ip']}:{flow_info['dst_port']} {flow_info['protocol']}")
                        else:
                            log_detection(f"流量特征提取失败，跳过此流量")
                    except Exception as e:
                        log_detection(f"处理流量数据失败: {e}")
                        import traceback
                        traceback.print_exc()
                        db_thread.rollback()
                log_detection(f"批量处理完成，成功处理 {len(flows)} 个流量")
            except Exception as e:
                log_detection(f"批量处理流量失败: {e}")
                import traceback
                traceback.print_exc()
                db_thread.rollback()
            finally:
                db_thread.close()
        
        # 启动定期处理线程
        def periodic_process():
            nonlocal processed_flows
            while capture_service.is_capturing():
                time.sleep(update_interval)
                if capture_service.is_capturing():
                    # 获取所有流量
                    flows = capture_service.get_flows()
                    if flows:
                        # 只处理未处理过的流量
                        new_flows = []
                        for flow in flows:
                            flow_key = (flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol)
                            if flow_key not in processed_flows:
                                # 只处理已完成的或有足够数据的流量
                                if flow.is_complete or (flow.fwd_packet_count + flow.bwd_packet_count) >= 5:
                                    new_flows.append(flow)
                                    processed_flows.add(flow_key)
                        
                        if new_flows:
                            log_detection(f"定期处理 {len(new_flows)} 个新流量")
                            process_batch_flows_with_db(new_flows)
                        else:
                            log_detection(f"没有新的流量需要处理")
        
        import threading
        process_thread = threading.Thread(target=periodic_process)
        process_thread.daemon = True
        process_thread.start()
        
        return {"success": True, "message": f"实时捕获已启动，更新间隔: {update_interval}秒"}
    else:
        return {"success": False, "message": "捕获已在进行中"}

@router.post("/stop-realtime")
def stop_realtime_capture(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """停止实时捕获"""
    from app.services.detection_service import DetectionService
    from app.services.strategy_service import StrategyService
    
    flows = capture_service.stop_capture()
    
    # 处理剩余的流量
    if flows:
        log_detection(f"处理剩余的 {len(flows)} 个流量")
        for flow in flows:
            try:
                features = flow.extract_features()
                if features:
                    feature_array = np.array(list(features.values()))
                    attack_type, confidence, threat_level = model_service.predict(feature_array)
                    
                    flow_info = flow.get_flow_info()
                    traffic_data = {
                        "src_ip": flow_info['src_ip'],
                        "src_port": flow_info['src_port'],
                        "dst_ip": flow_info['dst_ip'],
                        "dst_port": flow_info['dst_port'],
                        "protocol": flow_info['protocol'],
                        "packet_size": flow_info['packet_size'],
                        "status": "abnormal" if attack_type != "BENIGN" else "normal",
                        "attack_type": attack_type,
                        "confidence": confidence
                    }
                    TrafficService.create_traffic(db, traffic_data)
                    
                    # 自动执行策略
                    strategy_result = StrategyService.auto_execute_strategy(
                        db, attack_type, threat_level, flow_info['src_ip']
                    )
                    response_strategy = strategy_result['strategy_name'] if strategy_result else None
                    
                    # 存入检测结果表
                    detection_data = {
                        "src_ip": flow_info['src_ip'],
                        "src_port": flow_info['src_port'],
                        "dst_ip": flow_info['dst_ip'],
                        "dst_port": flow_info['dst_port'],
                        "protocol": flow_info['protocol'],
                        "packet_size": flow_info['packet_size'],
                        "attack_type": attack_type,
                        "confidence": confidence,
                        "threat_level": threat_level,
                        "response_strategy": response_strategy
                    }
                    DetectionService.create_detection(db, detection_data)
            except Exception as e:
                print(f"处理流量数据失败: {e}")
    
    return {"success": True, "message": f"实时捕获已停止，处理了 {len(flows)} 个流量"}

@router.get("/realtime-status")
def get_realtime_status(current_user = Depends(get_current_user)):
    """获取实时捕获状态"""
    return {
        "is_capturing": capture_service.is_capturing(),
        "flow_count": capture_service.get_flow_count()
    }

@router.get("/protocol-distribution")
def get_protocol_distribution(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """获取协议类型分布"""
    distribution = TrafficService.get_protocol_distribution(db)
    return {"distribution": distribution}

@router.get("/attack-distribution")
def get_attack_distribution(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """获取攻击类型分布"""
    distribution = TrafficService.get_attack_distribution(db)
    return {"distribution": distribution}

@router.get("/src-ip-distribution")
def get_src_ip_distribution(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """获取源IP分布"""
    distribution = TrafficService.get_src_ip_distribution(db)
    return {"distribution": distribution}

@router.get("/dst-ip-distribution")
def get_dst_ip_distribution(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """获取目的IP分布"""
    distribution = TrafficService.get_dst_ip_distribution(db)
    return {"distribution": distribution}

@router.get("/dst-port-distribution")
def get_dst_port_distribution(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """获取目的端口分布"""
    distribution = TrafficService.get_dst_port_distribution(db)
    return {"distribution": distribution}
