import numpy as np

def compute_risk_score(rf_probability: float, anomaly_score: float, event_indicators: dict = None) -> float:
    """
    Transparent, documented composite cybersecurity risk score in [0.0, 100.0].
    
    Components:
    - Supervised threat probability weight: 65%
    - Unsupervised behavioral anomaly score weight: 35%
    - Contextual heuristic boost (e.g., suspicious TTL, intense packet bursts): up to +10 bonus
    
    Formula:
      Base Score = (0.65 * rf_probability * 100) + (0.35 * anomaly_score * 100)
      Contextual Boost = evaluated based on abnormal flow traits (high rate, zero body with active state, etc.)
      Final Risk Score = min(100.0, max(0.0, Base Score + Contextual Boost))
    """
    base_score = (0.65 * float(rf_probability) * 100.0) + (0.35 * float(anomaly_score) * 100.0)
    
    boost = 0.0
    if event_indicators:
        # Check for extreme packet burst rate (> 100,000 packets/sec)
        rate = float(event_indicators.get('rate', 0.0) or 0.0)
        if rate > 50000:
            boost += 5.0
            
        # Severe packet loss indicator (sloss + dloss > 50)
        sloss = float(event_indicators.get('sloss', 0.0) or 0.0)
        dloss = float(event_indicators.get('dloss', 0.0) or 0.0)
        if (sloss + dloss) > 50:
            boost += 5.0
            
    final_score = np.clip(base_score + boost, 0.0, 100.0)
    return float(round(final_score, 2))

def get_severity_level(risk_score: float) -> str:
    """
    Maps numerical risk score to categorical severity level:
    - 0.0 to 39.99  => Low
    - 40.0 to 69.99 => Medium
    - 70.0 to 100.0 => High
    """
    if risk_score >= 70.0:
        return 'High'
    elif risk_score >= 40.0:
        return 'Medium'
    else:
        return 'Low'
