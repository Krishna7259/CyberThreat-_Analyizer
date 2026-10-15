import numpy as np
from sklearn.ensemble import IsolationForest

def train_isolation_forest(X_train, contamination=0.15, random_state=42):
    """
    Fits an Isolation Forest model on feature matrix.
    contamination: expected proportion of outliers / anomalies in the traffic dataset.
    """
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1
    )
    iso_forest.fit(X_train)
    return iso_forest

def compute_anomaly_scores(iso_forest: IsolationForest, X):
    """
    Computes normalized anomaly score in [0.0, 1.0] and binary anomaly flag.
    - decision_function returns negative values for anomalies, positive for inliers.
    - Anomaly score: higher score represents higher anomalous deviation.
    """
    # Raw decision scores: higher is more normal, lower/negative is anomalous
    raw_scores = iso_forest.decision_function(X)
    
    # Invert and normalize: shift so minimum is 0, scale appropriately
    # Typically raw_scores range from ~ -0.3 to +0.3
    # Sigmoidal or min-max normalization:
    # A standard formula: 1 / (1 + exp(5 * raw_scores)) maps 0 (boundary) to 0.5, negative to >0.5
    anomaly_scores = 1.0 / (1.0 + np.exp(6.0 * raw_scores))
    anomaly_scores = np.clip(anomaly_scores, 0.0, 1.0)
    
    # Binary predictions: -1 is anomaly, 1 is inlier
    preds = iso_forest.predict(X)
    is_anomaly = (preds == -1)
    
    return anomaly_scores, is_anomaly
