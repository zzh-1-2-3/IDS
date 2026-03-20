THREAT_WEIGHTS = {
    "BENIGN": {"harm": 0.0, "urgency": 0.0, "misjudgment_cost": 1.0},
    "Bot": {"harm": 0.95, "urgency": 0.9, "misjudgment_cost": 0.1},
    "BruteForce": {"harm": 0.75, "urgency": 0.75, "misjudgment_cost": 0.3},
    "DoS": {"harm": 0.95, "urgency": 0.95, "misjudgment_cost": 0.15},
    "Infiltration": {"harm": 0.98, "urgency": 0.95, "misjudgment_cost": 0.05},
    "PortScan": {"harm": 0.5, "urgency": 0.4, "misjudgment_cost": 0.5},
    "WebAttack": {"harm": 0.9, "urgency": 0.9, "misjudgment_cost": 0.15},
}

W_HARM = 0.45
W_URGENCY = 0.4
W_MISJUDGMENT = 0.05
W_CONFIDENCE = 0.1


def calculate_threat_score(attack_type: str, confidence: float) -> float:
    if attack_type not in THREAT_WEIGHTS:
        attack_type = "BENIGN"
    
    weights = THREAT_WEIGHTS[attack_type]
    
    # 对于正常流量，置信度越高分数越低；对于异常流量，置信度越高分数越高
    if attack_type == "BENIGN":
        # 正常流量使用(1 - confidence)作为置信度因子
        confidence_factor = 1 - confidence
    else:
        # 异常流量使用confidence作为置信度因子
        confidence_factor = confidence
    
    score = (
        W_HARM * weights["harm"] +
        W_URGENCY * weights["urgency"] +
        W_MISJUDGMENT * weights["misjudgment_cost"] +
        W_CONFIDENCE * confidence_factor
    )
    
    return round(score, 4)


def get_threat_level(score: float) -> str:
    if score < 0.3:
        return "none"
    elif score < 0.6:
        return "low"
    elif score < 0.9:
        return "medium"
    else:
        return "high"


def get_threat_level_chinese(score: float) -> str:
    if score < 0.3:
        return "无危害"
    elif score < 0.6:
        return "低危"
    elif score < 0.9:
        return "中危"
    else:
        return "高危"


def evaluate_threat(attack_type: str, confidence: float) -> tuple:
    score = calculate_threat_score(attack_type, confidence)
    level = get_threat_level(score)
    level_chinese = get_threat_level_chinese(score)
    
    return score, level, level_chinese


if __name__ == "__main__":
    test_cases = [
        ("BENIGN", 1.0),  # 100%置信度的正常流量
        ("BENIGN", 0.95),
        ("BENIGN", 0.7),  # 70%置信度的正常流量
        ("Bot", 0.90),
        ("BruteForce", 0.85),
        ("DoS", 0.88),
        ("Infiltration", 0.88),
        ("PortScan", 0.78),
        ("WebAttack", 0.82),
    ]
    
    print("攻击类型\t\t置信度\t得分\t威胁等级")
    print("-" * 50)
    for attack_type, conf in test_cases:
        score, level, level_cn = evaluate_threat(attack_type, conf)
        print(f"{attack_type}\t\t{conf}\t{score}\t{level_cn}")
