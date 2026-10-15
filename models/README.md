# CyberShield AI Model Directory

This directory stores serialized machine learning artifacts, pipelines, and evaluation metrics for real-time intrusion detection and anomaly analysis.

## Files

1. `preprocessor.joblib`:
   - Scikit-learn `ColumnTransformer` pipeline.
   - Handles numerical median imputation and Z-score standardization (`StandardScaler`).
   - Handles categorical one-hot encoding (`OneHotEncoder(handle_unknown='ignore')`) across network protocols (`proto`), services (`service`), and connection states (`state`).

2. `random_forest.joblib`:
   - Supervised `RandomForestClassifier` with 100 decision trees.
   - Outputs predicted class (`0` = Normal, `1` = Suspicious) and calibrated prediction probabilities.

3. `isolation_forest.joblib`:
   - Unsupervised `IsolationForest` anomaly detector.
   - Detects unusual, out-of-distribution traffic patterns without relying on predefined attack signatures.
   - Computes continuous decision function and inverted anomaly score in [0.0, 1.0].

4. `metrics.json`:
   - Performance metrics evaluated strictly on the held-out 20% test split:
     - Accuracy
     - Precision
     - Recall
     - F1-Score
     - False Positive Rate (FPR)
     - Confusion Matrix (TN, FP, FN, TP)

5. `metadata.json`:
   - Training timestamp, dataset name, feature dimensions, model version, and random seed.
