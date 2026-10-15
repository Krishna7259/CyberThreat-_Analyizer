import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

# Ensure root directory is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import Config
from ml.preprocessing import (
    validate_dataset_schema,
    clean_and_prepare_df,
    build_preprocessing_pipeline,
    TARGET_COLUMN,
    CATEGORY_COLUMN
)
from ml.anomaly_detection import train_isolation_forest
from ml.evaluate import evaluate_model
from database.db_models import db, ModelVersion
from database.init_db import create_app

def train_pipeline(dataset_path: str, model_version: str = Config.MODEL_VERSION):
    print(f"[*] Starting model training pipeline using: {dataset_path}")
    df = pd.read_csv(dataset_path)
    
    is_valid, missing, msg = validate_dataset_schema(df)
    if not is_valid:
        print(f"[-] Validation error: {msg}")
        sys.exit(1)
        
    print(f"[+] Dataset validated successfully. Total records: {len(df)}")
    
    # Clean data
    df_clean = clean_and_prepare_df(df)
    
    # Ensure label column exists
    if TARGET_COLUMN not in df.columns:
        print(f"[-] Error: Target column '{TARGET_COLUMN}' not found in dataset.")
        sys.exit(1)
        
    y = df[TARGET_COLUMN].astype(int)
    
    # Train / Test split (80/20) with fixed random seed to prevent data leakage
    X_train_df, X_test_df, y_train, y_test = train_test_split(
        df_clean, y, test_size=0.20, random_state=Config.RANDOM_STATE, stratify=y
    )
    
    print(f"[*] Train set size: {len(X_train_df)}, Test set size: {len(X_test_df)}")
    
    # Fit preprocessing pipeline
    print("[*] Fitting preprocessing ColumnTransformer pipeline...")
    preprocessor = build_preprocessing_pipeline()
    X_train_trans = preprocessor.fit_transform(X_train_df)
    X_test_trans = preprocessor.transform(X_test_df)
    
    # 1. Train Random Forest Classifier
    print("[*] Training Random Forest Threat Classifier (n_estimators=100)...")
    start_time = time.time()
    rf_clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        random_state=Config.RANDOM_STATE,
        n_jobs=-1,
        class_weight='balanced'
    )
    rf_clf.fit(X_train_trans, y_train)
    rf_duration = time.time() - start_time
    print(f"[+] Random Forest training completed in {rf_duration:.2f}s")
    
    # 2. Train Isolation Forest on normal baseline traffic from train set
    print("[*] Fitting Isolation Forest Anomaly Detector...")
    normal_mask = (y_train == 0)
    X_train_normal = X_train_trans[normal_mask] if normal_mask.sum() > 20 else X_train_trans
    iso_forest = train_isolation_forest(X_train_normal, contamination=0.10, random_state=Config.RANDOM_STATE)
    print("[+] Isolation Forest anomaly detector trained successfully.")
    
    # Evaluate Random Forest on held-out test set
    print("[*] Evaluating classifier on held-out test set...")
    y_pred = rf_clf.predict(X_test_trans)
    y_proba = rf_clf.predict_proba(X_test_trans)[:, 1] if rf_clf.classes_.size > 1 else y_pred
    
    metrics = evaluate_model(y_test, y_pred, y_proba)
    print("\n--- MODEL EVALUATION RESULTS ---")
    print(f"Accuracy:               {metrics['accuracy'] * 100:.2f}%")
    print(f"Precision:              {metrics['precision'] * 100:.2f}%")
    print(f"Recall:                 {metrics['recall'] * 100:.2f}%")
    print(f"F1-Score:               {metrics['f1_score'] * 100:.2f}%")
    print(f"False Positive Rate:    {metrics['false_positive_rate'] * 100:.2f}%")
    print(f"Confusion Matrix:       TN={metrics['confusion_matrix']['true_negatives']}, FP={metrics['confusion_matrix']['false_positives']}, FN={metrics['confusion_matrix']['false_negatives']}, TP={metrics['confusion_matrix']['true_positives']}")
    print("--------------------------------\n")
    
    # Save models and preprocessor
    models_dir = Config.MODELS_FOLDER
    models_dir.mkdir(parents=True, exist_ok=True)
    
    preprocessor_path = models_dir / 'preprocessor.joblib'
    rf_path = models_dir / 'random_forest.joblib'
    iso_path = models_dir / 'isolation_forest.joblib'
    metrics_path = models_dir / 'metrics.json'
    metadata_path = models_dir / 'metadata.json'
    
    joblib.dump(preprocessor, preprocessor_path)
    joblib.dump(rf_clf, rf_path)
    joblib.dump(iso_forest, iso_path)
    
    with open(metrics_path, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, indent=2)
        
    metadata = {
        'version': model_version,
        'algorithm': 'Random Forest Classifier + Isolation Forest Anomaly Detector',
        'dataset_name': Path(dataset_path).name,
        'features_count': X_train_trans.shape[1],
        'training_samples': len(X_train_df),
        'test_samples': len(X_test_df),
        'training_date': datetime.now(timezone.utc).isoformat(),
        'rf_estimators': 100,
        'random_state': Config.RANDOM_STATE
    }
    
    with open(metadata_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
        
    print(f"[+] Saved artifacts to {models_dir}")
    
    # Record Model Version in database
    app = create_app()
    with app.app_context():
        existing_version = ModelVersion.query.filter_by(version=model_version).first()
        if existing_version:
            existing_version.algorithm = metadata['algorithm']
            existing_version.dataset_name = metadata['dataset_name']
            existing_version.training_date = datetime.now(timezone.utc)
            existing_version.evaluation_metrics = json.dumps(metrics)
        else:
            new_version = ModelVersion(
                version=model_version,
                algorithm=metadata['algorithm'],
                dataset_name=metadata['dataset_name'],
                training_date=datetime.now(timezone.utc),
                evaluation_metrics=json.dumps(metrics)
            )
            db.session.add(new_version)
        db.session.commit()
        print(f"[+] Model version '{model_version}' recorded in database.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="CyberShield AI Model Training Pipeline")
    parser.add_argument('--dataset', type=str, default='datasets/unsw_nb15_sample.csv', help="Path to training dataset CSV")
    parser.add_argument('--version', type=str, default=Config.MODEL_VERSION, help="Model version identifier")
    args = parser.parse_args()
    
    train_pipeline(args.dataset, args.version)
